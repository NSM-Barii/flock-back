# THIS MODULE WILL BE USED FOR FLOCK DRIVING


# UI IMPORTS
from rich.table import Table
from rich.live import Live 
from rich.panel import Panel


# BT IMPORTS
from bleak import BleakScanner


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
#


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

                    if raven_uuid == uuid[0]:

                        if cls.verbose: console.print(f"[bold red][+] Found Raven UUID:[bold yellow] {uuid}")
                        services.append(raven_uuid); uuids.append(uuid)
                    
                            
                
                if len(services) > 0: return True, services
                    
                return False, False
        

        except Exception as e:
            console.print(f"[bold red]Exception Error:[bold yellow] {e}")
            return False, False


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
            

            with LOCK:
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
                await asyncio.sleep(Variables.ble_scan_duration)
                await scanner.stop()
                devices = scanner.discovered_devices_and_advertisement_data




                if not devices: continue
   

                for mac, (device, adv) in devices.items():

                    if not adv: continue

                    local_name = adv.local_name
                    rssi = adv.rssi
                    uuid = adv.service_uuids or False

                    manufacturer = BLE_Sniffer._get_manuf(manuf=adv.manufacturer_data)
                    a, valid_uuid = PDU_Inspector._check_uuid(uuid=uuid)
                    time_stamp = Utilities.get_timestamp()

                    data = {
                        "time_stamp": time_stamp,
                        "type": "ble",
                        "rssi": rssi,
                        "mac": mac,
                        "local_name": local_name,
                        "manufacturer": manufacturer,
                        "uuids": valid_uuid
                    }

                    txt = '  '.join((
                        time_stamp,
                        "type: ble",
                        f"rssi: {rssi}",
                        f"mac: {mac}",
                        f"local_name: {local_name}",
                        f"manufacturer: {manufacturer}"
                    ))

                    if mac not in cls.macs:

                        cls.macs.append(mac)

                        # ARE YOU FLOCK or AI ???
                        if PDU_Inspector.controller(type=1, data=data, ssid=False, mac=mac, ble_name=local_name, uuid=uuid):
                            cls.flock_macs.append(mac)
                            DataBase.push_device(save_data=data)
                            Variables.ai_cameras_all["ble"].append(data)

                        elif cls.verbose: console.print(f"[bold red][-] Non AI Camera (BLE):[bold yellow] {data}")

                    elif (Variables.packet) and (mac in cls.flock_macs): console.print(f"[bold cyan][PKT] AI Camera (BLE):[yellow] {data}"); DataBase.push_packet(save_data=data)
                        

        except KeyboardInterrupt as e: console.print(f"[bold red] Keyboard Exception Error:[bold yellow] {e}")
        except Exception as e:console.print(f"[bold red] BLE Exception Error:[bold yellow] {e}"); return

            

        
         
    @classmethod
    def main(cls, verbose, scan_duration=5, timeout=2):
        """This method will be resposnible for looping through ble_scan <-- scan"""


        # VARS
        cls.verbose = verbose
        scans = 1
        cls.macs = []
        cls.flock_macs = []



        console.print("[bold green][+] Starting BLE_Sniffer"); time.sleep(1)
        asyncio.run(BLE_Sniffer.ble_scan(timeout=scan_duration)); scans += 1
        console.print(f"[bold red][-] Killed -->[bold yellow] BLE_Sniffer")





class WiFi_Sniffer():

    done = False
    DataBase = DataBase.WiFi

    @classmethod
    def _line_parser(cls, line):
        """Parse tshark output line"""


        parts = line.strip().split("\t")

        if len(parts) < 9: return


        time_epoch = parts[0]
        src        = parts[1]
        dst        = parts[2]
        raw_ssid   = parts[3].strip() or False
        rssi       = max((int(x) for x in parts[4].split(",") if x), default=0)
        channel    = parts[5]
        freq       = parts[6]
        subtype    = parts[7]
        seq        = parts[8]

        if not src or src == "ff:ff:ff:ff:ff:ff": return

        cls.frame_counts[src] = cls.frame_counts.get(src, 0) + 1
        

        ssid       = cls.DataBase.get_ssid(raw_ssid=raw_ssid)
        vendor     = cls.DataBase.get_vendor_main(mac=src)
        encryption = "unknown"  # THIS WILL BE TO COMPLICATED TO GET WITH TSHARK
        time_stamp = Utilities.get_timestamp()

        data = {
            "time_stamp": time_stamp,
            "type": "wifi",
            "rssi": rssi,
            "mac": src,
            "ssid": ssid,
            "vendor": vendor,
            "frequency": freq,
            "encryption": encryption,
            "channel": channel,
            "subtype": subtype,
            "seq": seq,
            "frame_count": cls.frame_counts[src]
        }

        txt = '  '.join((
            time_stamp,
            "type: wifi",
            f"rssi: {rssi}",
            f"mac: {src}",
            f"ssid: {ssid}",
            f"channel: {channel}",
            f"frequency: {freq}",
            f"vendor: {vendor}"
        ))


        if src not in cls.macs:

            if ssid: cls.ssids.append(ssid)
            cls.macs.append(src)

            if PDU_Inspector.controller(type=2, data=data, ssid=ssid, mac=src, ble_name=False, uuid=False):
                cls.flock_macs.append(src)
                DataBase.push_device(save_data=data)
                Variables.ai_cameras_all["wifi"].append(data)
                return

            if cls.verbose: console.print(f"[bold red][-] Non AI Camera (WiFi): [yellow]{data}")


        elif (Variables.packet) and (src in cls.flock_macs): console.print(f"[bold cyan][PKT] AI Camera (WiFi):[yellow] {data}"); DataBase.push_packet(save_data=data)


    @classmethod
    def _wifi_scanner(cls, iface):
        """Tshark-based scanner"""


        cmd = [
            "tshark",
            "-i", iface,
            "-l",
            "-Y", "wlan.fc.type_subtype == 0x04 || wlan.fc.type_subtype == 0x08",
            "-T", "fields",
            "-e", "frame.time_epoch",
            "-e", "wlan.ta",
            "-e", "wlan.ra",
            "-e", "wlan.ssid",
            "-e", "radiotap.dbm_antsignal",
            "-e", "wlan_radio.channel",
            "-e", "wlan_radio.frequency",
            "-e", "wlan.fc.type_subtype",
            "-e", "wlan.seq"
        ]


        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )


        try:

            for line in process.stdout:

                if not Variables.BACKGROUND: break

                cls._line_parser(line)

        except Exception as e: console.print(f"[bold red][-] Tshark Error: {e}")
        finally: process.kill()



    @classmethod
    def main(cls, iface, verbose):
        """This will run class wide logic"""


        cls.macs = []
        cls.ssids = []
        cls.flock_macs = []
        cls.frame_counts = {}
        cls.verbose = verbose
        cls.ai_cameras = []


        if not iface: console.print("[bold red][+] Cancelling WiFi_Sniffer"); return
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
            time_duration = time.strftime("%Hh %Mm %Ss", time.gmtime(time.time() - time_start))

            time.sleep(0.1); console.print(f"\n[bold red][-] Killing Background Threads.....\n")

            total = len(Variables.ble_ai_cameras) + len(Variables.wifi_ai_cameras)

            console.print("[bold red] =====  Found AI Cameras  ===== \n")
            console.print(f"[bold yellow]BLE:[/bold yellow]   {len(Variables.ble_ai_cameras)}")
            console.print(f"[bold yellow]WiFi:[/bold yellow]  {len(Variables.wifi_ai_cameras)}")
            console.print(f"[bold green]Total:[/bold green] {total}\n")

            console.print(f"[bold green]Program Duration:[bold yellow] {time_duration}")






if __name__ == "__main__":
    Main_Thread.main()