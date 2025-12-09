# THIS WILL HOUSE SIDE UTILITIES FOR NON RADIO CODE


# UI IMPORTS
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich.console import Console
import pyfiglet
console = Console()

# NETWORK IMPORTS
import  requests
from scapy.all import sniff, RadioTap
from scapy.layers.dot11 import Dot11Elt


# ETC IMPORTS 
import threading, os, time, os, subprocess, json, argparse, textwrap
from gps3 import gps3
from datetime import datetime
from pathlib import Path



NAME = "flock-back"

# TEMP FIX FOR FILE CRASHING WITHOUT SUDO
try:
    USER_HOME = Path(os.getenv("SUDO_USER") and f"/home/{os.getenv('SUDO_USER')}") or Path.home()
    BASE_DIR = USER_HOME / "Documents" / "nsm_tools" / ".data" / f"{NAME}"
    GUI_DIR = USER_HOME / "Documents" / "nsm_tools" / f"{NAME}" / "gui" / "data"
except Exception as e:
    console.print(e)

    # SWITCH BACK TO PATH
    BASE_DIR = Path.home() / "Documents" / "nsm_tools" / ".data" / f"{NAME}"
    GUI_DIR = Path.home() / "Documents" / "nsm_tools" / f"{NAME}" / "gui" / "data"


BASE_DIR.mkdir(exist_ok=True, parents=True)
GUI_DIR.mkdir(exist_ok=True, parents=True)


class Settings():
    """This method will be responsible for controlling json info"""


    def __init__(self):
        pass


    
    @classmethod
    def get_json(cls, verbose=True):
        """This will pull and return json info"""


        
        # DESTROY ERRORS
        while True:
            try:

                # IF EXISTS
                if BASE_DIR.exists():


                    # MAKE SETTINGS
                    path = BASE_DIR / "settings.json"


                    with open(path, "r") as file:

                        settings = json.load(file)


                        if verbose:
                            console.print(f"Successfully Pulled settings.json from {path}", style="bold green")


                    return settings
                

                

                # MAKE PATHS
                else:

                    BASE_DIR.mkdir(exist_ok=True, parents=True)
            


            # MAKE JSON
            except FileNotFoundError as e:

                if verbose:
                    console.print(f"[bold red]FileNotFound Error:[yellow] {e}")

                

                Settings.create_json()


        
            
            # ERRORS
            except Exception as e:
                console.print(f"[bold red]Exception Error:[yellow] {e}")

                break


    @classmethod
    def push_json(cls, data, verbsoe=True):
        """This method will be used to push info to settings.json"""


        # VARS
        time_stamp = datetime.now().strftime("%m/%d/%Y - %I:%M:%S")


        # DESTROY ERRORS
        while True:
            try:

                # 
                if BASE_DIR.exists():
                    

                    # VARS
                    path = BASE_DIR / "settings.json"

                    with open(path, "w") as file:

                        json.dump(data, file, indent=4)


                        if verbsoe:
                            console.print("Successfully pushed settings.json", style="bold green")
                    

                    return



                
                # MAKE DIR
                else:

                    BASE_DIR.mkdir(exist_ok=True, parents=True)


                    if verbsoe:
                        console.print(f"Successfully created dir", style="bold green")
                
            


            except FileNotFoundError as e:

                if verbsoe:
                    console.print(f"[bold red]FileNotFound Error:[yellow] {e}")

                
                Settings.create_json()

                
            
            except Exception as e:
                console.print(f"[bold red]Exception Error:[yellow] {e}")
                
                break
    

    @classmethod
    def create_json(cls):
        """This is a sub method to be called upon when the json file is missing"""

        # CREATE VARS
        path = BASE_DIR / "settings.json"
        data = {
                "iface": "",
                "captures": ""
            }


        # PUSH IT 
        with open(path, "w") as file:

            json.dump(data, file, indent=4)
        

        # PERFECT
        console.print("Successfully created json file", style="bold green")

    
    @classmethod
    def push_txt(cls, data):
        """This method is just to make a new txt file with info"""

        
        # VAR
        verbose = True


        
        # LOOP FOR ERRORS
        while True:

            try:

                if BASE_DIR.exists():

                    path = BASE_DIR / ""


                    with open(path, "a") as file:
                        file.write(data)


                    if verbose:
                        console.print(f"Successfully appended info", style="bold green")

                    
                    break

                


                else:


                    BASE_DIR.mkdir()
            



            except Exception as e:
                console.print(f"[bold red]Exception Error:[yellow] {e}")

                break


class Recon_Pusher():
    """This class will be used to push data from recon mode"""

    
    def __init__(self):
        pass


    @classmethod
    def get_path(cls):
        """This will be responsible for creating path"""

        
        # VARS
        count = 1

        paths = BASE_DIR / "war_drives"
        paths.mkdir(exist_ok=True, parents=True)

        if BASE_DIR.exists():


            # GET A VALID FILE NAME
            while True:
                
                # CREATE PATH
                p = paths / f"drive_{count}.json"
                 
                # IF ITS FALSE WE KEEP THAT PATH
                if not p.exists():
                    break
                
                
                # += 
                count += 1
            

            # VERBOSE SHII
            #console.print(f"File: drive_{count}")
         

            # NOW RETURN PATH
            return p, count
    

    @classmethod
    def push_war(cls, save_data, CONSOLE, verbose=False):
        """This method live war results to front end gui"""

        # Write to data archive
        path_archive = BASE_DIR / "war_drives" / "live.json"

        # Write to GUI directory for web dashboard
        path_gui = GUI_DIR / "live.json"


        # PUSH TO BOTH LOCATIONS
        try:
            # Archive location
            with open(path_archive, "w") as file:
                json.dump(save_data, file, indent=4)

            # GUI location
            with open(path_gui, "w") as file:
                json.dump(save_data, file, indent=4)


                if verbose:
                    CONSOLE.print(f"[+] War Results Successfully pushed to archive & GUI", style="bold green")


        # DESTROY ERRORS
        except Exception as e:
            CONSOLE.print(f"[bold red]Exception Error:[bold yellow] {e}")
    

    
    
    @classmethod
    def push_to_gui(cls, save_data, CONSOLE, verbose=False):
        """This method will be used to push results from war driving"""

        path = cls.path


        # PUSH
        try:
            with open(path, "w") as file:
                json.dump(save_data, file, indent=4)

                
                if verbose:
                    CONSOLE.print(f"[+] War Results Succesfully pushed", style="bold green")
            
        
        # DESTROY ERRORS
        except Exception as e:
            CONSOLE.print(f"[bold red]Exception Error:[bold yellow] {e}")
    



    @classmethod
    def main(cls):
        """This will be called upon to init class vars"""

        # SET PATH
        cls.path, c = Recon_Pusher.get_path()


        # VERBOSE
        console.print(f"Recon init --> {c}", style="bold green")




class Utilities():
    """Utilities"""


    @classmethod
    def clear_screen(cls):
        """This will be responsible for clear screening"""


        if os.name == "posix": os.system("clear")
        else: os.system("cls")


    @classmethod
    def welcome_ui(cls, iface , text="    WiFi \nHacking", font="dos_rebel", c1="bold red", c2="bold purple", skip=False):
        """This method will house the welcome message"""


        # SET THE MODE
        mode = 1



        if mode == 1:


            # CREATE THE VAR
            welcome = pyfiglet.figlet_format(text=text, font=font)
            
            print('\n\n')
            console.print(welcome, style=c2)
            console.print(f"\n[bold red]Current iface:[bold green] {iface}\n\n")
            if skip == False:
                console.input("[bold red]Press ENTER to Sniff! ")
            print('\n')


        

        elif mode == 2:

            fonts = pyfiglet.FigletFont.getFonts()


            for f in fonts:

                welcome = pyfiglet.figlet_format(text=text, font=f)

                console.print(welcome, style=c2)

                console.print(f"[bold blue]Current Font:[bold green] {f}\n\n")
                

                if f == "dos_rebel":
                    t = 3
                
                else:

                    t = 0.3



                time.sleep(t)
 
    
    @staticmethod
    def welcome_message(font="dos_rebel"):
        """This will be the welcome message that is displayed within the main menu"""
        
        # FOR SPACE FROM TOP OF TERMINAL
        print("\n\n")

        # CREATE
        art1 = pyfiglet.figlet_format(text="     Flock", font=font)    
        art2 = pyfiglet.figlet_format(text="      Back", font=font)


        # PRINT
        console.print(art1, style="bold red")  
        console.print(art2, style="bold blue")
        
        

        console.print("        ========================================================================", style="bold blue")
        console.print(
        
           "            ===================  Developed by NSM Barii  ===================",
           style="bold red"

        )
        console.print("        ========================================================================", style="bold blue")


    @classmethod
    def get_interface(cls, verbose=False):
        """This method will be used to get the user interface and automatically create a file saving it for default use"""

        
        try:
            # SET DEFAULT IFACE IF AVAILABLE
            data = Settings.get_json(verbose=verbose)
            def_iface = data['iface']


            # GIVE OPTION FOR DEFAULT
            if def_iface != "":
                use = f"or press enter for {def_iface}"
            
            else:
                use = ""

            
            while True:
                iface = console.input(f"[bold blue]Enter iface {use}: ").strip()
                

                # NEED SOME TYPE OF IFACE
                if iface == "" and def_iface == "":

                    console.print("You must enter iface to procced silly", style="bold red")

                
                # ROLL BACK TO DEFAUT
                elif iface == "":
                    iface = def_iface

                    return iface
                

                
                # SET NEW DEF IFACE
                else:
                    data['iface'] = iface
                    
                    # NOW TO UPDATE SETTINGS
                    Settings.push_json(data=data)

                    return iface
            

        # ERROR 
        except Exception as e:
            console.print(f"[bold red]Exception Error:[yello] {e}")

    
    @staticmethod
    def _help_menu():


        Utilities.clear_screen()


        art = """  ___ _         _   ___          _   
 | __| |___  __| |_| _ ) __ _ __| |__
 | _|| / _ \/ _| / / _ \/ _` / _| / /
 |_| |_\___/\__|_\_\___/\__,_\__|_\_\
                                     """

        print(art)

        print(r"""
╔══════════════════════════════════════════════════════════════════╗
║                        AI Surveillance Hunter                    ║
║             Real-Time Detection of LPR / BLE / Wi-Fi Cameras     ║
╚══════════════════════════════════════════════════════════════════╝
[•] Developed by: NSM-Barii  (https://github.com/NSM-Barii)
[•] Contributions welcome: MACs, UUIDs, BLE names, vendors
        """)


    @classmethod
    def _get_monitor_mode(cls, iface, mode="monitor", verbose=False):
        """This will validate the iface given and try to put it in monitor mode"""

      
        subprocess.run(f"sudo ip link set {iface} down; sudo iw dev {iface} set type {mode}; sudo ip link set {iface} up", shell=True)
        subprocess.run('iwconfig', shell=True); time.sleep(1.5)

    

    @classmethod
    def _get_gps_cords(cls, timeout=10, verbose=False):
        """This will be used to get live gps cords"""


        gps_socket = gps3.GPSDSocket()
        data_stream = gps3.DataStream()
        gps_socket.connect()
        gps_socket.watch()


        for new_data in gps_socket:

            try:

                if new_data:
                    data_stream.unpack(new_data)
                    print('Altitude = ', data_stream.TPV['alt'])
                    print('Latitude = ', data_stream.TPV['lat'])
                        
            except StopIteration:
                break

            except Exception as e:
                if verbose:
                    console.print(f"[bold red]GPS Exception Error: {e}")
                time.sleep(0.5)
                continue
                    


        return None, None



    @classmethod
    def get_args(cls):
        """This method will be responsible for pulling args for iface and gps"""
        

        parser = argparse.ArgumentParser(
        description="Flockback: Detect BLE & Wi-Fi LPR surveillance devices.",
        add_help=False 
        )
        parser.add_argument("-h", action="store_true", help="Display help, usage info, and project banner")
        parser.add_argument("-i", required=False, help="Monitor-mode wireless interface to use for scanning (e.g., wlan1)")
        parser.add_argument("-g", required=False, help="(Optional) Serial port path for GPS module (e.g., /dev/ttyUSB0)" )      
        parser.add_argument("-v", required=False, action="store_true",help="Verbose mode, where more information is shown on non AI Cameras the devices in your surround.")


        args = parser.parse_args()
        iface = args.i or False
        gps =   args.g or False
        help =  args.h or False
        verbose = args.v or False

        if help: Utilities._help_menu();  parser.print_help(); exit()
        if iface: Utilities._get_monitor_mode(iface=iface)
       #  lat, lon, alt = Utilities._get_gps_cords()
      #  console.print(lat, lon, alt); exit()

        return iface, gps, verbose
    



class Background_Threads():
    """This module will house background permanent running threads"""
    

    # CLASS VARIABLES
    hop = True
    channel = 0




    @classmethod
    def get_channel(cls, pkt):
        """This will be used to get the ssid channel"""


        elt = pkt[Dot11Elt]
        channel = 0


        while isinstance(elt, Dot11Elt):

            if elt.ID == 3:
                channel = elt.info[0]
                return channel
            
            elt = elt.payload
        
        return False

    

    @classmethod
    def get_freq(cls, freq):
        """This will return frequency"""


        if freq in range(2412, 2472): return "2.4 GHz"
        elif freq in range(5180, 5825): return "5 GHz"
        else: return "6 GHz"


    @staticmethod
    def get_rssi(pkt, format=False):
        """This method will be responsible for pulling signal strength"""

        signal = ""; signal = f"[bold red]Signal:[/bold red] {signal}"  

        
        # CHECK FOR RADIO HEADER
        if pkt.haslayer(RadioTap):
            

            # PULL RSSI
            rssi = getattr(pkt, "dBm_AntSignal", False)
            
            # NOW RETURN
            if rssi:

                if format:
                    return f"{rssi} dBm"
                
                return rssi





    @classmethod
    def get_encryption(cls, pkt):
        """Get this encryption"""







    @classmethod
    def channel_hopper(cls, set_channel=False, verbose=False):
        """This method will be responsible for automatically hopping channels"""



        def hopper():

            delay = 0.25
            all_hops = [1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161]

            iface = Settings.get_json(verbose=False)['iface']


            # TUNE HOP
            if set_channel:


                cls.hop = False; time.sleep(2)


                try:

                    subprocess.Popen(
                    ["sudo", "iw", "dev", iface, "set", "channel", str(set_channel)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL,
                    start_new_session=True
                )

                except Exception as e:
                    console.print(f"[bold red]Exception Error:[bold yellow] {e}")
   

            # AUTO HOPPING
            while cls.hop:

                for channel in all_hops:


                    try:
                    

                        # HOP CHANNEL
                        subprocess.Popen(
                            ["sudo", "iw", "dev", iface, "set", "channel", str(channel)],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            stdin=subprocess.DEVNULL,
                            start_new_session=True
                        )
                        cls.channel = channel
                        if verbose:
                            console.print(f"[bold green]Hopping on Channel:[bold yellow] {channel}")

                        # DELAY
                        time.sleep(delay)
                    
                    except Exception as e:
                        console.print(f"[bold red]Exception Error:[bold yellow] {e}")



        threading.Thread(target=hopper, args=(), daemon=True).start()
        cls.hop = True

