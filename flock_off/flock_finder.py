# THIS MODULE WILL BE USED FOR FLOCK DRIVING


# UI IMPORTS
from rich.table import Table
from rich.live import Live 
from rich.panel import Panel
from rich.console import Console
console = Console()



# BT IMPORTS
from bleak import BleakScanner


# WIFI IMPORTS
from scapy.all import sniff, Ether, RadioTap
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11Deauth, Dot11ProbeReq


# ETC IMPORTS
import time, asyncio, threading, subprocess
from datetime import datetime


# NSM SAME-MODULE IMPORTS
from signatures import FLOCK_SIGNATURES
from utilities import Utilities, Background_Threads, Recon_Pusher



# NSM MODULE IMPORTS
#from nsm_modules.nsm_utilities import Background_Threads, NetTilities
#from nsm_modules.nsm_utilities import Utilities as nsm_utilities
#from nsm_modules.nsm_deauth import Frame_Snatcher



# GLOBAL LOCK
LOCK = threading.Lock()



class PDU_Inspector():
    """This class will be responsible for called upon methods"""


    # TESTING ONLY
    verbose = False

    
    # DATA
    wifi_ssid_patterns = FLOCK_SIGNATURES["wifi_ssid_patterns"]
    mac_prefixes = FLOCK_SIGNATURES["mac_prefixes"]
    ble_name_patterns = FLOCK_SIGNATURES["ble_name_patterns"]
    raven_service_uuids = FLOCK_SIGNATURES["raven_service_uuids"]



    @classmethod
    def _check_ssid(cls, ssid):
        """This method will be responsible for matching prefixes == ssid"""


        for camera_ssid in cls.wifi_ssid_patterns:

            if camera_ssid == ssid:

                if cls.verbose: console.print(f"[bold red][+] Found SSID Name:[bold yellow] {ssid}")

                return True
        
        return False


    @classmethod
    def _check_mac(cls, mac:str):
        """This method will be resposnible for matching prefixes == mac"""


        for flock_mac in cls.mac_prefixes:

            if flock_mac == mac:

                if cls.verboose: console.print(f"[bold red][+] Found Flock MAC:[bold yellow] {mac}")
                 
                return True
            
        return False
    
    
    @classmethod
    def _check_ble_name(cls, ble_name):
        """This method will be responsible for matching prefixes == ble_name"""



        for camera_name in cls.ble_name_patterns:

            if camera_name == ble_name:

                if cls.verbose: console.print(f"[bold red][+] Found BLE Name:[bold yellow] {ble_name}")


                return True
            
        
        return False


    @classmethod
    def _check_uuid(cls, uuid):
        """This metod will be responsible for matching prefixes == uuid(s)"""


        if len(uuid) > 1:


            for id in uuid:

                for raven_uuid in cls.raven_service_uuids:

                    if raven_uuid == id:
                        
                        if cls.verbose: console.print(f"[bold red][+] Found Raven UUID:[bold yellow] {uuid}")
                    
                        
                        return True
                
            return False
        

        else:

            for raven_uuid in cls.raven_service_uuids:

                if raven_uuid == uuid:
                    
                    if cls.verbose: console.print(f"[bold red][+] Found Raven UUID:[bold yellow] {uuid}")
                
                    
                    return True
            
            return False

    

    @classmethod
    def controller(cls, type, data, ssid=False, mac=False, ble_name=False, uuid=False):
        """This method will be the ultimate controller of all sub methods"""

        
        # BOOL CHECK DATA
        check_ssid = PDU_Inspector._check_ssid(ssid=ssid)            if ssid else False
        check_mac = PDU_Inspector._check_mac(mac=mac)                     if mac else False
        check_ble_name = PDU_Inspector._check_ble_name(ble_name=ble_name) if ble_name else False
        check_uuid = PDU_Inspector._check_uuid(uuid=uuid)                 if uuid else False



        #return check_ssid, check_mac, check_ble_name, check_uuid
    
        
        if check_ssid or check_mac or check_ble_name or check_uuid:

            space = "    "

            if type == 1:  console.print(f"\n[bold green][+] Found AI Camera (BLE):[bold yellow] {data}"); BLE_Sniffer.ai_cameras.append(data)
            elif type == 2: console.print(f"\n[bold green][+] Found AI Camera (WiFi):[bold yellow] {data}"); WiFi_Sniffer.ai_cameras.append(data)
    

            if check_ssid: console.print(f"{space}[bold green][+] Match SSID:[bold yellow] {ssid}")  
            else: console.print(f"{space}[bold red][-] Match SSID:[bold yellow] {ssid if ssid else False}")
            if check_mac: console.print(f"{space}[bold green][+] Match MAC:[bold yellow] {mac}") 
            else: console.print(f"{space}[bold red][-] Match MAC:[bold yellow] {mac if mac else False}")
            if check_ble_name: console.print(f"{space}[bold green][+] Match BLE_name:[bold yellow] {ble_name}") 
            else: console.print(f"{space}[bold red][-] Match BLE_name:[bold yellow] {ble_name if ble_name else False}")
            if check_uuid: console.print(f"{space}[bold green][+] Match UUID(s):[bold yellow] {uuid}") 
            else: console.print(f"{space}[bold red][-] Match UUID(s):[bold yellow] {uuid if uuid else False    }")

            #if vendor: console.print(f"{space}[bold green][+] Extra Info Vendor:[bold yellow] {vendor}") 
            #else: console.print(f"{space}[bold red][-] Match Vendor:[bold yellow] False")


            return True
        
        return False
    

class BLE_Sniffer():
    """This class will be responsible for findning ble devices"""



    @staticmethod
    def _clean_manuf(manuf):
        """clean manuf data"""

        manuf_new = {}

        for cid, payload in manuf.items():

            manuf_new[cid] = payload.hex()
            console.print(cid, payload)



    @classmethod
    def _reset_ble(cls, duration=2.5, verbose=False):
        """This will be called upon to fix ble crashing issues"""

        command = "bluetoothctl"


        if  time.time() - cls.last_flush > duration * 60:


            subprocess.run(["sudo", f"{command}", "power", "off"])
            subprocess.run(["sudo", f"{command}", "power", "on"])

            cls.last_flush = time.time()

            if verbose: console.print("[+] BLE FLushed", style="bold green")
        
        #console.print(cls.last_flush)

    
    @staticmethod
    async def _pause_ble(duration=1):
        """Small delay to stop congestion"""

        await asyncio.sleep(duration)


    @staticmethod
    async def _discover(timeout):
        """internal scanner"""
        
        try:
            return await BleakScanner.discover(timeout=timeout, return_adv=True)
        
        except Exception as e:
            console.print(f"[bold red]Exception Error:[bold red] {e}")


    @classmethod
    def ble_scan(cls, timeout=5):
        """This will sniff for ble advertisements traversing our surroundings"""

        
        devices = asyncio.run(BLE_Sniffer._discover(timeout=timeout))
        asyncio.run(BLE_Sniffer._pause_ble())


        if not devices: return

        #BLE_Sniffer._reset_ble()

        

        try:

            # PARSE DATA
            for mac, (device, adv) in devices.items():


                if mac not in cls.ble_devices and adv:  

                    cls.ble_devices.append(mac)
                    
                    #manuf = BLE_Sniffer._clean_manuf(manuf=adv.manufacturer_data)

                    

                    # STORE VARS
                    local_name = adv.local_name
                    rssi = adv.rssi
                    manufacturer = adv.manufacturer_data
                    services = adv.service_uuids

                    data = {
                        "mac": mac,
                        "rssi": rssi,
                        "local_name": local_name,
                        "manufacturer": manufacturer,
                        "services": services
                    }


                    # ARE YOU FLOCK or AI ??? 
                    with LOCK:
                        if PDU_Inspector.controller(type=1, data=data, ssid=False, mac=mac, ble_name=local_name, uuid=services): 
                            Main_Thread.ai_cameras_all["ble"] = data; return
                            
                    
                    if cls.verbose:
                        console.print(f"[bold red][-] Non AI Camera (BLE):[bold yellow] {data}")     
                
                        
        except KeyboardInterrupt as e:
            console.print(f"[bold red]Exception Error:[bold yellow] {e}")
        
        except Exception as e:
            console.print(f"[bold red]Exception Error:[bold yellow] {e}"); return

            
            BLE_Sniffer._pause_ble(duration=5)
            BLE_Sniffer._reset_ble()

            BLE_Sniffer._reset_ble(duration=5)

            return           

        
         
    @classmethod
    def main(cls, verbose=True, scan_duration=5, timeout=2):
        """This method will be resposnible for looping through ble_scan <-- scan"""


        # VARS
        cls.verbose = verbose
        scans = 1
        cls.last_flush = time.time()
        cls.ble_devices = []
        cls.ai_cameras = []



        console.print("[bold green][+] Starting BLE_Sniffer")


        while Main_Thread.BACKGROUND:


            BLE_Sniffer.ble_scan(timeout=scan_duration); scans += 1

            time.sleep(timeout)
        
        console.print(f"[bold red][-] Killed -->[bold yellow] BLE_Sniffer")



class WiFi_Sniffer():
    """This class will be responsible for finding wifi devices"""

    done = False
    

    @classmethod
    def _reset_adapter(cls, iface):
        """This will be responsible for bringing back up and resetting the adapter"""


        Utilities._get_monitor_mode(iface=iface)


    @classmethod
    def _packet_parser(cls, pkt):
        """This will be responsible for parsing packets"""

        
        def _parser():

            if pkt.haslayer(Dot11Beacon):

                addr1 = pkt[Dot11].addr1 if pkt[Dot11].addr1 != "ff:ff:ff:ff:ff:ff" else False
                addr2 = pkt[Dot11].addr2 if pkt[Dot11].addr2 != "ff:ff:ff:ff:ff:ff" else False

                ssid = pkt[Dot11Elt].info.decode(errors="ignore") or False


                channel = Background_Threads.get_channel(pkt=pkt)
                #vendor = nsm_utilities.get_vendor(mac=addr2)
                rssi = Background_Threads.get_rssi(pkt=pkt)
                encryption = Background_Threads.get_encryption(pkt=pkt)
                freq = Background_Threads.get_freq(freq=pkt[RadioTap].ChannelFrequency)

                data = {
                    "ssid": ssid,
                    "frequency": freq,
                    "encryption": encryption,
                    "channel": channel,
                    "rssi": rssi
                }

                if not ssid or not channel:
                    return

                if ssid and addr2 not in cls.macs: 
                    
                    cls.beacons.append(ssid)
                    cls.macs.append(addr2)
                    Main_Thread.ai_cameras_all["wifi"] = data

                    with LOCK:
                        if PDU_Inspector.controller(type=2, data=data, ssid=ssid, mac=addr2, ble_name=False, uuid=False): return

                    if cls.verbose:
                        console.print(f"[bold red][-] Non AI Camera (WiFi):[bold yellow] {data}")
                
                
        
        if  Main_Thread.BACKGROUND: threading.Thread(target=_parser, args=(), daemon=True).start()
        if not cls.done and not Main_Thread.BACKGROUND: cls.done = True; return KeyboardInterrupt
        

    @classmethod
    def _wifi_scan(cls, iface):
        """This will perform a wifi scan"""

        attempts = 0

        
        while True:

            try:

                attempts += 1

                if cls.verbose:
                    console.print(f"Attempt #{attempts}")

                sniff(iface=iface, store=0, prn=WiFi_Sniffer._packet_parser, timeout=15); time.sleep(0.5)
            

            except OSError as e:
                console.print(f"[bold red]OS Error:[bold yellow] {e}")

                WiFi_Sniffer._reset_adapter(iface=iface); time.sleep(5)        #BLE_Sniffer._reset_ble()
                # from main import Main_UI; Main_UI.main_menu()
                

            
            except KeyboardInterrupt as e:
                console.print(f"[bold red][-] Killed -->[bold yellow] WiFi Sniffer")
                break
            
            except Exception as e:
                console.print(f"[bold red]Exception Error:[bold yellow] {e}")
                break
    

    @classmethod
    def main(cls, iface, verbose=True):
        """This method will be responsible for running wifi_scan <-- """

          # VARS
        cls.verbose = verbose
        cls.macs = []
        cls.beacons = []
        cls.ai_cameras = []


        if not iface: console.print("[bold red][+] Cancelling WiFi_Sniffer");  return
        console.print("[bold green][+] Starting WiFi_Sniffer")


        Background_Threads.channel_hopper()

        WiFi_Sniffer._wifi_scan(iface=iface)

        console.print(f"[bold red][-] Killed -->[bold yellow] WiFi_Sniffer")


class Main_Thread():
    """This class will be the main class in charge of sub classess"""


    @classmethod
    def main(cls, iface, verbose):
        """Get shit done"""

        cls.BACKGROUND = True; cls.ai_cameras_all = {}
        Recon_Pusher.main()
        time_stamp = datetime.now().strftime("%m/%d/%Y - %H:%M:%S"); time_start = time.time()
        console.print(f"[bold green]Timestamp:[bold yellow] {time_stamp}\n")


        # WIFI SNIFFER
        threading.Thread(target=WiFi_Sniffer.main, args=(iface, verbose), daemon=True).start()
        

        # BLE SNIFFER
        threading.Thread(target=BLE_Sniffer.main, args=(verbose,), daemon=True).start()

        
        #time.sleep(.5); console.print(f"[bold green][+] ALL Background Threads Started")

        try:                           # PUSH UPDATE
            while True: 
                all = []; all.append(BLE_Sniffer.ai_cameras); all.append(WiFi_Sniffer.ai_cameras)

                print(cls.ai_cameras_all)
                Recon_Pusher.push_war(save_data=all, CONSOLE=console)
                time.sleep(5)
            
            

        except KeyboardInterrupt as e:

            cls.BACKGROUND = False
            time_duration = time.time() - time_start
            time.sleep(0.1); console.print(f"\n[bold red][-] Killing Background Threads.....\n")
            
            console.print('[bold red] =====  Found AI Cameras  ===== \n')
            total = len(BLE_Sniffer.ai_cameras); total += len(WiFi_Sniffer.ai_cameras); minutes = total / 60
            console.print(f"[bold yellow]BLE:[/bold yellow] {len(BLE_Sniffer.ai_cameras)}\n[bold yellow]WiFi:[/bold yellow] {len(WiFi_Sniffer.ai_cameras)}\n[bold green]Total AI Cameras:[/bold green] {total}")
            console.print(f"\n[bold yellow]BLE_Sniffer:[/bold yellow] {BLE_Sniffer.ai_cameras}", f"\n\n[bold yellow]WiFi_Sniffer:[/bold yellow] {WiFi_Sniffer.ai_cameras}")
             

            console.print(f"\n\n[bold green]Program Duration:[bold yellow] {time_duration:.2f} seconds - {minutes} minutes\n[bold green]Timestamp:[bold yellow] {time_stamp}")




if __name__ == "__main__":
    Main_Thread.main()