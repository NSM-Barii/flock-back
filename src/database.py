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
from scapy.layers.dot11 import Dot11Elt, Dot11Beacon


# ETC IMPORTS 
import threading, os, time, os, subprocess, json, argparse, textwrap, manuf
from gps3 import gps3
from datetime import datetime
from pathlib import Path



# NSM IMPORTS
from vars import Variables


# CONSTANTS
console = Variables.console
LOCK    = Variables.LOCK
NAME = "flock-back"





class DataBase():
    """This will be a database for service uuids"""


    database = Path(__file__).parent.parent / "database" / "bluetooth_sig" / "assigned_numbers" / "company_identifiers"
    company_ids_path = database / "company_ids.json"


    class WiFi():
        """This is for WiFi for sub class"""


        encryption_cache = {}


        @staticmethod
        def get_encryption_tshark(protected, rsn, akm, wep):
            """Parse tshark fields into encryption type"""

            try:
                if wep == "1":
                    return "WEP"

                if rsn:
                    if akm:
                        
                        if "8" in akm or "9" in akm:
                            return "WPA3"
                        return "WPA2"
                    return "WPA2"

                if protected == "1":
                    return "WPA"

                return "OPEN"

            except Exception:
                return "UNKNOWN"
        

        @classmethod
        def update_encryption(cls, mac, new_enc):
            """Track best known encryption per device"""

            if mac not in cls.encryption_cache:
                cls.encryption_cache[mac] = new_enc
                return new_enc

            current = cls.encryption_cache[mac]

            priority = {
                "OPEN": 0,
                "WEP": 1,
                "WPA": 2,
                "WPA2": 3,
                "WPA3": 4,
                "UNKNOWN": -1
            }

            if priority.get(new_enc, -1) > priority.get(current, -1):
                cls.encryption_cache[mac] = new_enc

            return cls.encryption_cache[mac]
                    
        
        
        @classmethod
        def get_ssid(cls, raw_ssid):
            """This will return ssid"""


            if raw_ssid:
                try:
                    ssid = bytes.fromhex(raw_ssid).decode("utf-8", errors="ignore")
                except:
                    ssid = raw_ssid
            else:
                ssid = False

            
            return ssid

    
        @classmethod
        def _get_vendor(cls, mac: str, verbose=True) -> str:
            """MAC --> Vendor | lookup"""
            
            try:

                manuf_path = str(Path(__file__).parent.parent / "database" / "manuf_old.txt")

                vendor = manuf.MacParser(manuf_path).get_manuf_long(mac=mac)
                
                if verbose:
                    console.print(f"Manuf.txt pulled -> {manuf_path}")            
                    console.print(f"[bold green][+] Vendor Lookup:[/bold green] {vendor} -> {mac}")
                

                return vendor
                    
            

            except FileNotFoundError:
                console.print(f"[bold red][-] Failed to pull manuf.txt:[bold yellow] File not Found!"); exit()
        
            
            except Exception as e:
                console.print(f"[bold red][-] Exception Error:[bold yellow] {e}"); exit()
        

        @staticmethod
        def _get_vendor_new(mac: str, verbose=True) -> str:
            """MAC Prefixes --> Vendor"""
            

            try:

                manuf_path = str(Path(__file__).parent.parent / "database" / "manuf_ring_mast4r.txt")

                mac_prefix = mac.split(':'); prefix = mac_prefix[0] + mac_prefix[1] + mac_prefix[2]


                with open(manuf_path, "r") as file:

                    for line in file:
                        parts = line.strip().split('\t')
                        
                        if parts[0] == prefix:

                            vendor = parts[1]

                            if verbose: console.print(f"[bold green][+] {parts[0]} --> {vendor}" )
                            
                            return vendor


            except FileNotFoundError:
                console.print(f"[bold red][-] Failed to pull manuf.txt:[bold yellow] File not Found!"); exit()
        

            except Exception as e:
                console.print(f"[bold red][-] Exception Error:[bold yellow] {e}")
        

        @staticmethod
        def get_vendor_main(mac: str, verbose=False) -> str:
            """This will use ringmast4r and wireshark vendor database"""


            vendor = DataBase.WiFi._get_vendor(mac=mac, verbose=verbose) or False; c = 1

            if not vendor: vendor = DataBase.WiFi._get_vendor_new(mac=mac, verbose=verbose) or False; c = 2 

            return vendor
        
    
    class Bluetooth():
        """This will be the subclass for bluetooth"""

            
        @staticmethod
        def _importer(file_path: str, type="json", verbose=True) -> any:
            """This method will be responsble for returning all file paths"""

            
            if type == "json":
                with open(file_path, "r") as file:
                    
                    data = json.load(file)

                    if verbose: console.print(f"[bold green][+] Successfully pulled: {file_path}")

                    return data 
            

        @staticmethod
        def _services():
            """This will house the database for service uuids"""

            
            services = [
                {
                    "name": "Tuya",
                    "uuid": "fd50",
                    "notes": "Used in cheap BLE smart locks, plugs, bulbs, and scales sold under dozens of brands.",
                    "likelihood": "Very High"
                },
                {
                    "name": "Xiaomi",
                    "uuid": "fd21",
                    "notes": "Used in BLE sensors and fitness trackers. Common in Mijia/Mi Band devices.",
                    "likelihood": "High"
                },
                {
                    "name": "Xiaomi (MiBeacon)",
                    "uuid": "fe95",
                    "notes": "BLE advertisement extension. Seen in multiple Xiaomi ecosystem devices.",
                    "likelihood": "High"
                },
                {
                    "name": "Fitbit",
                    "uuid": "fd6f",
                    "notes": "Used in fitness trackers for sync and telemetry.",
                    "likelihood": "Medium"
                },
                {
                    "name": "Tile",
                    "uuid": "fe9f",
                    "notes": "Custom protocol for encrypted BLE location beacons.",
                    "likelihood": "Medium"
                },
                {
                    "name": "Oura Ring",
                    "uuid": "fd88",
                    "notes": "Used for health data sync over BLE from biometric rings.",
                    "likelihood": "Medium"
                },
                {
                    "name": "Amazon Echo Buds",
                    "uuid": "fdcf",
                    "notes": "Custom telemetry + control services for earbuds.",
                    "likelihood": "Low"
                },
                {
                    "name": "Garmin",
                    "uuid": "fd19",
                    "notes": "Used in fitness watches and sensors with proprietary ANT+/BLE profiles.",
                    "likelihood": "Medium"
                },
                {
                    "name": "Apple (Find My)",
                    "uuid": "fdc0",
                    "notes": "Used in AirTags and Find My-enabled BLE devices.",
                    "likelihood": "Low"
                },
                {
                    "name": "Samsung",
                    "uuid": "fee0",
                    "notes": "Health device sync and BLE watch pairing.",
                    "likelihood": "Medium"
                },
                {
                    "name": "Nordic Semiconductor",
                    "uuid": "fd3d",
                    "notes": "Often shows up in DIY firmware. Some devices use it for OTA or control.",
                    "likelihood": "High"
                },
                {
                    "name": "Withings",
                    "uuid": "fdc1",
                    "notes": "Used in smart scales, BP monitors, and watches.",
                    "likelihood": "Medium"
                },
                {
                    "name": "Anker Soundcore",
                    "uuid": "fd12",
                    "notes": "Controls BLE headphone settings, EQ, and firmware.",
                    "likelihood": "Medium"
                },
                {
                    "name": "Google (Fast Pair)",
                    "uuid": "fdaf",
                    "notes": "Used in Android Fast Pair BLE handshake.",
                    "likelihood": "Low"
                }
            ]
            

            return services


        @staticmethod
        def _etcs() -> str:
            """Hold data"""

            mappings = {
                "12020002": "Apple Watch (device class)",
                "12020003": "Apple Audio Accessory (e.g. AirPods)",
                "12020000": "Apple Setup Device (generic)",
                "10063b1d": "Apple Nearby/Continuity rotating ID"
            }

            return mappings 
    

        @classmethod
        def _get_service_uuids(cls, uuid: any) -> str:
            """this will take given services and parse them through known database"""


            pass
        

        @classmethod
        def _get_uuids_main(cls, CONSOLE: str, uuid:any, verbose=False) -> any:
            """Are uuids vulnerable and or mapable"""



            services = DataBase._services()


            if len(uuid) > 1:

                for service in services:
                    for id in uuid:

                        if id == service: 

                            if verbose: CONSOLE.print(f"[bold green][+] Mapped service:[bold yellow] uuid <--> {service} ")

                            return service           

                return False
            

            else:
                
                for service in service:

                    if uuid == service: 
                        if verbose: CONSOLE.print(f"[bold green][+] Mapped service:[bold yellow] uuid <--> {service} ")

                        return service        

                return False



        @classmethod
        def _get_etc(cls, data: any, verbose=False) -> str:
            """etc --> model"""

            mapping = DataBase._etcs()

            for key, value in mapping.items():

                if data == key:

                    if verbose: console.print(f"[+] Found: {key} --> {value}")

                    return value
                

        @staticmethod
        def get_manufacturer(id, data, verbose=False) -> str:
            """This will convert manuf data -> manuf"""



            try:

                path = Path(__file__).parent.parent / "database" / "bluetooth_sig" / "assigned_numbers" / "company_identifiers" / "company_ids.json"
                
                if not path.exists(): console.print("[bold red][-] Database Error: BLE path doesnt exist"); return False
                

                with open(str(path), "r") as file:
                    company_ids = json.load(file)
        

                for key, value in company_ids.items():

                    if int(key) == int(id):

                        manufacturer = value["company"]

                        if verbose: console.print(f"[bold green][+] {id} --> {manufacturer}")
                        
                        #if data: return f"{manufacturer} | {data}"
                        return manufacturer
                
                return False



            except Exception as e: console.print(f"[bold red][-] Database Exception Error:[bold yellow] {e}")
    


    @classmethod
    def push_device(cls, save_data, verbose=True):
        """This method live war results to front end gui"""

       
        path = Path(__file__).parent.parent / "database" / "flocks.txt"  

        
        try:
                
            if not path.exists():
                with open(str(path), "w") as file:file.write("===  FLOCK Captures  ===\n\n"); console.print(f"[bold green][+]  flocks.txt successfully made")

        
            with open(str(path), "a") as file: file.write(f"\n{save_data}")

            if verbose: console.print(f"[+] War Results Successfully pushed to: {path}", style="bold green")
            

        except Exception as e: console.print(f"[bold red]Exception Error:[bold yellow] {e}")
    


  





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



        mode = 1


        if mode == 1:


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
        
   
        print("\n\n")


        art1 = pyfiglet.figlet_format(text="     Flock", font=font)    
        art2 = pyfiglet.figlet_format(text="      Back", font=font)



        console.print(art1, style="bold red")  
        console.print(art2, style="bold blue")
        
        

        console.print("        ========================================================================", style="bold blue")
        console.print(
        
           "            ===================  Developed by NSM Barii  ===================",
           style="bold red"

        )
        console.print("        ========================================================================", style="bold blue")
    

    @staticmethod
    def get_timestamp():
        """Simple universal method for returning timestamp"""

        time_stamp = datetime.now().strftime("%m/%d/%Y  -  %H:%M:%S"); return time_stamp



    @staticmethod
    def help_menu():


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
    def get_monitor_mode(cls, iface, mode="monitor", verbose=False):
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
                        
            except StopIteration: break

            except Exception as e:
                if verbose:
                    console.print(f"[bold red]GPS Exception Error: {e}")
                time.sleep(0.5)
                continue
                    


        return None, None



class Background_Threads():
    """This module will house background permanent running threads"""
    


    hop = True
    channel = 0


    @classmethod
    def channel_hopper(cls, iface, set_channel=False, verbose=False):
        """This method will be responsible for automatically hopping channels"""



        def hopper():

            delay = 0.25
            all_hops = [1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161]


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

                except Exception as e: console.print(f"[bold red]Exception Error:[bold yellow] {e}")
                

                return False

            while cls.hop:

                for channel in all_hops:


                    try:
                    
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

                        time.sleep(delay)
                    
                    except Exception as e: console.print(f"[bold red]Exception Error:[bold yellow] {e}")


        threading.Thread(target=hopper, args=(), daemon=True).start()
        cls.hop = True

