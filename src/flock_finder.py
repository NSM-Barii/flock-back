# THIS MODULE WILL BE USED FOR FLOCK DRIVING


# UI IMPORTS
from rich.table import Table
from rich.live import Live 
from rich.panel import Panel


# BT IMPORTS
from bleak import BleakScanner


# WIFI IMPORTS
from scapy.all import sniff, Ether, RadioTap
from scapy.layers.dot11 import Dot11, Dot11Elt, Dot11Beacon, Dot11ProbeResp, Dot11ProbeReq, Dot11Deauth


# ETC IMPORTS
import time, asyncio, threading, subprocess
from datetime import datetime


# NSM SAME-MODULE IMPORTS
from vars import Variables
from signatures import FLOCK_SIGNATURES
from database import Utilities, Background_Threads, DataBase



# CONSTANTS
console = Variables.console
LOCK    = Variables.LOCK



class PDU_Inspector():
    """This class will be responsible for called upon methods"""


    # TESTING ONLY
    verbose = False

    
    # DATA
    wifi_ssid_patterns  = FLOCK_SIGNATURES["wifi_ssid_patterns"]
    mac_prefixes        = FLOCK_SIGNATURES["mac_prefixes"]
    ble_name_patterns   = FLOCK_SIGNATURES["ble_name_patterns"]
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

            if mac.upper().startswith(flock_mac.upper()):

                if cls.verbose: console.print(f"[bold red][+] Found Flock MAC:[bold yellow] {mac}")

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

        services = []
        uuids = []
        
        try:

            if not uuid or uuid == None or len(uuid) == 0: return False, False

            if len(uuid) > 1:


                for id in uuid:

                    for raven_uuid in cls.raven_service_uuids:

                        if raven_uuid == id:
                            
                            if cls.verbose: console.print(f"[bold red][+] Found Raven UUID:[bold yellow] {uuid}")
                            services.append(raven_uuid); uuids.append(uuid) # <-- NOT IN USE (YET)
                        
                            
                
                if len(services) > 0: return True, services
                    
                return False, False
            

            else:



                for raven_uuid in cls.raven_service_uuids:

                    if raven_uuid == uuid:
                        
                        if cls.verbose: console.print(f"[bold red][+] Found Raven UUID:[bold yellow] {uuid}")
                        services.append(raven_uuid); uuids.append(uuid)
                    
                            
                
                if len(services) > 0: return True, services
                    
                return False, False
        

        except Exception as e:
            console.print(f"[bold red]Exception Error:[bold yellow] {e}")
            

    @classmethod
    def controller(cls, type, data, ssid=False, mac=False, ble_name=False, uuid=False):
        """This method will be the ultimate controller of all sub methods"""

        
        # BOOL CHECK DATA
        check_ssid = PDU_Inspector._check_ssid(ssid=ssid)                 if ssid else False
        check_mac = PDU_Inspector._check_mac(mac=mac)                     if mac else False
        check_ble_name = PDU_Inspector._check_ble_name(ble_name=ble_name) if ble_name else False
        check_uuid, services = PDU_Inspector._check_uuid(uuid=uuid)    

        
        if check_ssid or check_mac or check_ble_name or check_uuid:

            space = "    "

            if type == 1:  console.print(f"\n[bold green][+] Found AI Camera (BLE):[bold yellow] {data}");   Variables.ble_ai_cameras.append(data)
            elif type == 2: console.print(f"\n[bold green][+] Found AI Camera (WiFi):[bold yellow] {data}"); Variables.wifi_ai_cameras.append(data)
    

            if check_ssid: console.print(f"{space}[bold green][+] Match SSID:[bold yellow] {ssid}")  
            else: console.print(f"{space}[bold red][-] Match SSID:[bold yellow] {ssid if ssid else False}")
            if check_mac: console.print(f"{space}[bold green][+] Match MAC:[bold yellow] {mac}") 
            else: console.print(f"{space}[bold red][-] Match MAC:[bold yellow] {mac if mac else False}")
            if check_ble_name: console.print(f"{space}[bold green][+] Match BLE_name:[bold yellow] {ble_name}") 
            else: console.print(f"{space}[bold red][-] Match BLE_name:[bold yellow] {ble_name if ble_name else False}")
            if check_uuid: console.print(f"{space}[bold green][+] Match UUID(s):[bold yellow] {services}") 
            else: console.print(f"{space}[bold red][-] Match UUID(s):[bold yellow] {uuid}")


            return True
        
        return False
    


class BLE_Sniffer():
    """This class will be responsible for findning ble devices"""


    DataBase = DataBase.Bluetooth




    @classmethod
    def _get_manuf(cls, manuf):
        """This will parse and get manuf"""


    
        if not manuf: return False

        for key, value in manuf.items():
            id = key; hex = value.hex()
        


        company = cls.DataBase.get_manufacturer(id=id, data=hex)


        return company



    @classmethod
    async def ble_scan(cls, timeout=5):
        """This will sniff for ble advertisements traversing our surroundings"""


        try:

            scanner = BleakScanner()
            

            while Variables.BACKGROUND:

                await scanner.start()
                await asyncio.sleep(5)
                await scanner.stop()
                devices = scanner.discovered_devices_and_advertisement_data




                if not devices: return
                # PARSE DATA
                for mac, (device, adv) in devices.items():


                    if mac not in cls.ble_devices and adv:

                        cls.ble_devices.append(mac)

                        # STORE VARS
                        local_name = adv.local_name
                        rssi = adv.rssi
                        uuid = adv.service_uuids or False

                        manufacturer = BLE_Sniffer._get_manuf(manuf=adv.manufacturer_data)
                        a, valid_uuid = PDU_Inspector._check_uuid(uuid=uuid)
                        time_stamp = Utilities.get_timestamp()
        
                        data = {
                            "type": "ble",
                            "rssi": rssi,
                            "mac": mac,
                            "local_name": local_name,
                            "manufacturer": manufacturer,
                            "uuids": valid_uuid,
                            "time_stamp": time_stamp
                        }

                        txt = (
                            time_stamp,
                            f"type: ble",
                            f"rssi: {rssi}",
                            f"mac: {mac}",
                            f"local_name: {local_name}",
                            f"manufacturer: {manufacturer}"
                        )

                        txt = '  '.join(txt)


                        # ARE YOU FLOCK or AI ??? 
                        with LOCK:
                            if PDU_Inspector.controller(type=1, data=data, ssid=False, mac=mac, ble_name=local_name, uuid=uuid): 
                                DataBase.push_device(save_data=txt)
                                Variables.ai_cameras_all["ble"].append(data)
                                
                        
                        if cls.verbose: console.print(f"[bold red][-] Non AI Camera (BLE):[bold yellow] {data}")     
                    
                        
        except KeyboardInterrupt as e: console.print(f"[bold red] Keyboard Exception Error:[bold yellow] {e}")
        except Exception as e:console.print(f"[bold red] BLE Exception Error:[bold yellow] {e}"); return

            

        
         
    @classmethod
    def main(cls, verbose, scan_duration=5, timeout=2):
        """This method will be resposnible for looping through ble_scan <-- scan"""


        # VARS
        cls.verbose = verbose
        scans = 1
        cls.ble_devices = []



        console.print("[bold green][+] Starting BLE_Sniffer"); time.sleep(1)
        asyncio.run(BLE_Sniffer.ble_scan(timeout=scan_duration)); scans += 1
        console.print(f"[bold red][-] Killed -->[bold yellow] BLE_Sniffer")



class WiFi_Sniffer():
    """This will be a new class to account for flock changing"""
 
  
    done = False
    DataBase = DataBase.WiFi


    """
    addr1 == dst address
    addr2 == src address
    addr3 == src address
    
    Dot11Beacon        == beacons being sent from router -> broadcast
    Dot11ProbeRequest  == probes being sent from client -> router
    Dot11ProbeResponse == probes being responded to by client -> router



    Flock cameras advertising via hidden ssids will be found by macs that match flock OUIs
    Flock cameras 
    
    """



    @classmethod
    def _packet_parser(cls, pkt):
        """This will parse 802.11 frames"""



        def _parser():
            """function to be called upon by main method off class"""

            
            addr1 = pkt[Dot11].addr1 if pkt[Dot11].addr1 != "ff:ff:ff:ff:ff:ff" else False
            addr2 = pkt[Dot11].addr2 if pkt[Dot11].addr2 != "ff:ff:ff:ff:ff:ff" else False


            if not addr1 and not addr2: return False


            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeReq) or pkt.haslayer(Dot11ProbeResp):

                

                # SSID THATS IN BEACON OR PROBE-REQUEST
                ssid = pkt[Dot11Elt].info.decode(errors="ignore") or False
            
                channel    = Background_Threads.get_channel(pkt=pkt)
                vendor     = cls.DataBase.get_vendor_main(mac=addr2)
                rssi       = Background_Threads.get_rssi(pkt=pkt)
                encryption = Background_Threads.get_encryption(pkt=pkt)
                freq       = Background_Threads.get_freq(freq=pkt[RadioTap].ChannelFrequency)
                time_stamp = Utilities.get_timestamp()

                data = {
                    "type": "wifi",
                    "rssi": rssi,
                    "mac": addr2,
                    "ssid": "f",
                    "vendor": vendor,
                    "frequency": freq,
                    "encryption": encryption,
                    "channel": channel,
                    "time_stamp": time_stamp
                }

                txt = (
                    time_stamp,
                    f"type: wifi",
                    f"rssi: {rssi}",
                    f"mac: {addr2}",
                    f"ssid: {ssid}",
                    f"vendor: {vendor}"
                )

                txt = '  '.join(txt)


                #if not ssid or not channel: return

                if ssid or addr2 and addr2 not in cls.macs:
                    
                    cls.ssids.append(ssid)
                    cls.macs.append(addr2)

                    with LOCK:
                        if PDU_Inspector.controller(type=2, data=data, ssid=ssid, mac=addr2, ble_name=False, uuid=False): 
                            DataBase.push_device(save_data=txt)
                            Variables.ai_cameras_all["wifi"].append(data); return False
 

                    if cls.verbose: console.print(f"[bold red][-] Non AI Camera (WiFi):[bold yellow] {data}")
            

        if  Variables.BACKGROUND: threading.Thread(target=_parser, args=(), daemon=True).start()
        if not cls.done and not Variables.BACKGROUND: cls.done = True; return KeyboardInterrupt
        


    @classmethod
    def _wifi_scanner(cls, iface):
        """This will begin wifi scanning"""

        
        num = 0

        
        while Variables.BACKGROUND:

            try:

                if cls.verbose: console.print(f"[+] Starting sniffer instance: #{num}"); num += 1
                sniff(iface=iface, store=0, prn=cls._packet_parser, timeout=15); time.sleep(0.3)
            

            except Exception as e: console.print(f"[bold red][-] Exception Error:[bold yellow] {e}"); break


    @classmethod
    def main(cls, iface, verbose):
        """This will start class wide logic"""


        cls.macs = []
        cls.ssids = []
        cls.verbose = verbose
        cls.ai_cameras = []


        if not iface: console.print("[bold red][+] Cancelling WiFi_Sniffer");  return
        console.print("[bold green][+] Starting WiFi_Sniffer"); time.sleep(1)


        Background_Threads.channel_hopper(iface=iface)

        cls._wifi_scanner(iface=iface)



class Main_Thread():
    """This class will be the main class in charge of sub classess"""


    @classmethod
    def main(cls):
        """Get shit done"""


        bface   = Variables.bface
        iface   = Variables.iface
        verbose = Variables.verbose


        #Recon_Pusher.main() 
        time_start = time.time()
        time_stamp = datetime.now().strftime("%m/%d/%Y - %H:%M:%S")
        console.print(f"[bold green]Timestamp:[bold yellow] {time_stamp}\n")
        
        

        # WIFI SNIFFER 
        threading.Thread(target=WiFi_Sniffer.main, args=(iface, verbose), daemon=True).start()
        

        # BLE SNIFFER
        threading.Thread(target=BLE_Sniffer.main, args=(verbose,), daemon=True).start()


     


        try:
            # WEB SERVER
            from server import Web_Server; time.sleep(.4)
            Web_Server.start()            
            

        except KeyboardInterrupt as e:

            Variables.BACKGROUND = False
            time_duration = time.time() - time_start
            #TIME = datetime
            
            time.sleep(0.1); console.print(f"\n[bold red][-] Killing Background Threads.....\n")
            
            total = len(Variables.ble_ai_cameras); total += len(Variables.wifi_ai_cameras)
            console.print('[bold red] =====  Found AI Cameras  ===== \n')
            console.print(f"[bold yellow]BLE:[/bold yellow] {len(Variables.ble_ai_cameras)}\n[bold yellow]WiFi:[/bold yellow] {len(Variables.wifi_ai_cameras)}\n[bold green]Total AI Cameras:[/bold green] {total}")
            console.print(f"\n[bold yellow]BLE_Sniffer:[/bold yellow] {Variables.ble_ai_cameras}", f"\n\n[bold yellow]WiFi_Sniffer:[/bold yellow] {Variables.wifi_ai_cameras}")
             

            console.print(f"\n\n[bold green]Program Duration:[bold yellow] {time_duration}") # - {minutes} minutes\n[bold green]Timestamp:[bold yellow] {time_stamp}")






if __name__ == "__main__":
    Main_Thread.main()