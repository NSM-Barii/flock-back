# THIS WILL HOUSE UI CODE


# IMPORTS
import argparse


# NSM MODULES
from vars import Variables
from database import Utilities
from flock_finder import Main_Thread


class Main_UI():
    """This module will be responsible for housing UI code"""



    @classmethod
    def main_menu(cls):
        """This will be the main menu before booting in"""



        parser = argparse.ArgumentParser(
        description="Flockback: Detect BLE & Wi-Fi LPR surveillance devices.",
        add_help=False 
        )
        parser.add_argument("-h", action="store_true", help="Display help, usage info, and project banner")
        parser.add_argument("-b", required=False, help="Bluetooth adapter to use for ble scanning (hci0)")
        parser.add_argument("-i", required=False, help="Monitor-mode wireless interface to use for scanning (e.g., wlan1)")
        parser.add_argument("-g", required=False, help="(Optional) Serial port path for GPS module (e.g., /dev/ttyUSB0)" )      
        parser.add_argument("-v", required=False, action="store_true",help="Verbose mode, where more information is shown on non AI Cameras the devices in your surround.")


        args = parser.parse_args()

        help              = args.h or False
        Variables.bface   = args.b or "hci0"
        Variables.iface   = args.i or False
        Variables.gps     = args.g or False
        Variables.verbose = args.v or False



        if help: Utilities.help_menu();  parser.print_help(); exit()
        if Variables.iface: Utilities.get_monitor_mode(iface=Variables.iface)


        Utilities.clear_screen()
        Utilities.welcome_message(); print('\n\n')


        Main_Thread.main()



if __name__ == "__main__": Main_UI.main_menu()




        