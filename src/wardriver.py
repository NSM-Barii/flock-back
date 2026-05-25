# THIS MODULE WILL HOUSE WARDRIVER MODE FOR FLOCK-BACK
# AUTOMATICALLY DETECTS ALL MONITOR MODE ADAPTERS AND SPLITS CHANNELS BY BAND



# UI IMPORTS
from rich.panel import Panel


# ETC IMPORTS
import subprocess


# NSM IMPORTS
from vars import Variables
from database import Background_Threads


# CONSTANTS
console  = Variables.console

BAND_2_4     = [1, 6, 11]
BAND_5_LOW   = [36, 40, 44, 48]
BAND_5_HIGH  = [149, 153, 157, 161]




class Wardriver():
    """This will handle auto adapter detection and band splitting for wardriver mode"""


    AP_IFACE = "wlan0"


    @classmethod
    def _get_adapters(cls):
        """Detect all non-AP adapters, set to monitor mode, return list"""

        adapters = {}

        try:

            out   = subprocess.check_output(["iw", "dev"], text=True)
            iface = None

            for line in out.splitlines():
                line = line.strip()

                if line.startswith("Interface"):
                    iface = line.split()[1]
                elif line.startswith("type") and iface:
                    if iface != cls.AP_IFACE:
                        adapters[iface] = line.split()[1]
                    iface = None

        except Exception as e: console.print(f"[bold red][!] Adapter Detection Error:[bold yellow] {e}")

        monitor = []

        for iface, mode in adapters.items():

            if mode != "monitor":
                subprocess.run(["ip",  "link", "set", iface, "down"],            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["iw",  "dev",  iface, "set", "type", "monitor"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["ip",  "link", "set", iface, "up"],              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                console.print(f"[bold yellow][↑][/bold yellow]  [bold white]{iface}[/bold white]  [dim]->[/dim]  set to monitor")
            else:
                console.print(f"[bold green][✓][/bold green]  [bold white]{iface}[/bold white]  [dim]->[/dim]  monitor")

            monitor.append(iface)

        return monitor


    @classmethod
    def _split_channels(cls, ifaces):
        """Split channels by band across available adapters"""

        bands  = [BAND_2_4, BAND_5_LOW, BAND_5_HIGH]
        splits = {}

        if len(ifaces) == 1:
            splits[ifaces[0]] = BAND_2_4 + BAND_5_LOW + BAND_5_HIGH

        elif len(ifaces) == 2:
            splits[ifaces[0]] = BAND_2_4
            splits[ifaces[1]] = BAND_5_LOW + BAND_5_HIGH

        else:
            for i, iface in enumerate(ifaces):
                splits[iface] = bands[i] if i < len(bands) else BAND_2_4 + BAND_5_LOW + BAND_5_HIGH

        return splits


    @classmethod
    def main(cls):
        """Run from here"""


        console.print(Panel("WarDriver Mode", style="bold red", border_style="bold purple"))

        ifaces = cls._get_adapters()

        if not ifaces:
            console.print("[bold red][!] No monitor mode adapters found.[/bold red]")
            return False

        console.print(f"[bold green][+] Found {len(ifaces)} adapter(s): {', '.join(ifaces)}[/bold green]")

        splits = cls._split_channels(ifaces=ifaces)

        for iface, channels in splits.items():
            Variables.ifaces[iface] = channels
            console.print(f"[bold green][+][/bold green]  [bold white]{iface}[/bold white]  [dim]->[/dim]  [bold purple]{channels}[/bold purple]")
            Background_Threads.channel_hopper(iface=iface, channels=channels)

        return True
