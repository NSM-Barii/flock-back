# THIS WILL HOUSE UI CODE


# IMPORTS
import argparse
from pathlib import Path

# NSM MODULES
from vars import Variables
from database import Utilities
from flock_finder import Main_Thread

# CONSTANTS
console  = Variables.console
c1 = "bold green"
c2 = "bold yellow"
c3 = "bold red"
c4 = "bold blue"


class Main_UI():
    """This module will be responsible for housing UI code"""



    @classmethod
    def main_menu(cls):
        """This will be the main menu before booting in"""



        parser = argparse.ArgumentParser(
        description="Flockback: Detect BLE & Wi-Fi LPR surveillance devices.",
        add_help=False 
        )
        parser.add_argument("-h",     action="store_true", help="Display help, usage info, and project banner")
        parser.add_argument("-b",     required=False, help="Bluetooth adapter to use for ble scanning (hci0)")
        parser.add_argument("-i",     required=False, help="Monitor-mode wireless interface to use for scanning (e.g., wlan1)")
        parser.add_argument("-g",     required=False, help="(Optional) Serial port path for GPS module (e.g., /dev/ttyUSB0)")
        parser.add_argument("-p",     action="store_true", required=False, help="Continuously print packets from flock cameras even if already found")
        parser.add_argument("-v",     required=False, action="store_true", help="Verbose mode, shows info on non-AI cameras in your surroundings")
        parser.add_argument("-delay",  required=False, type=float, help="Channel hop dwell time in seconds (default: 0.125)")
        parser.add_argument("-hops",   required=False, nargs="+", type=int, help="List of channels to hop (default: 1 6 11 36 40 44 48 149 153 157 161)")
        parser.add_argument("-preset", required=False, choices=["2.4", "5", "all"], help="Channel hop preset: 2.4 (1-11), 5 (36-161), all (default list)")


        args = parser.parse_args()

        help              = args.h or False
        Variables.bface   = args.b   or "hci0"
        Variables.iface   = args.i   or False
        Variables.gps     = args.g   or False
        Variables.packet  = args.p   or False
        Variables.verbose = args.v   or False
        Variables.delay   = args.delay  if args.delay  is not None else Variables.delay
        Variables.hops    = args.hops   if args.hops   is not None else Variables.hops
        if args.preset: Variables.hops = Variables.presets[args.preset]



        if help: Utilities.help_menu();  parser.print_help(); exit()
        if Variables.iface: Utilities.get_monitor_mode(iface=Variables.iface)


        Utilities.clear_screen()
        Utilities.welcome_message(); print('\n\n')


        db_path     = Path(__file__).parent.parent / "database"
        flocks_path  = db_path / "flocks.json"
        packets_path = db_path / "packets.json"

        stats = (
            f"[{c1}] [+] WiFi Interface:[{c4}] {Variables.iface}"
            f"\n[{c1}] [+] BT Interface:[{c4}] {Variables.bface}"
            f"\n[{c1}] [+] Channels:[{c4}] {Variables.hops}"
            f"\n[{c1}] [+] Hop Delay:[{c4}] {Variables.delay}s"
            f"\n[{c1}] [+] Packet Mode:[{c4}] {bool(Variables.packet)}"
            f"\n[{c1}] [+] Verbose:[{c4}] {Variables.verbose}"
            f"\n[{c1}] [+] GPS:[{c4}] {Variables.gps}"
            f"\n[{c1}] [+] Flocks Save:[{c4}] {flocks_path}"
            f"\n[{c1}] [+] Packets Save:[{c4}] {packets_path}"
        )

        console.print(
            f"\n[{c1}]=========   CONSTANTS   =========\n",
            stats,
            f"\n[{c1}]=================================\n"
        )


        Main_Thread.main()



if __name__ == "__main__": Main_UI.main_menu()




        