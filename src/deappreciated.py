# THIS WILL HOUSE DEAPPRECIATED CODE THAT IM NOT YET READY TO GET RID OFF





# DEAPPRECIATED
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



# DEAPPRECIATED
class WiFi_Sniffer_old():
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
                time_stamp = Utilities.get_timestamp()

                data = {
                    "mac": addr2,
                    "ssid": ssid,
                    "frequency": freq,
                    "encryption": encryption,
                    "channel": channel,
                    "rssi": rssi,
                    "time_stamp": time_stamp
                }

                if not ssid or not channel:
                    return

                if ssid and addr2 not in cls.macs: 
                    
                    cls.beacons.append(ssid)
                    cls.macs.append(addr2)

                    with LOCK:
                        if PDU_Inspector.controller(type=2, data=data, ssid=ssid, mac=addr2, ble_name=False, uuid=False): 
                            Main_Thread.ai_cameras_all["wifi"].append(data)
                            return

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
                console.print(f"[bold red]WiFi LastException Error:[bold yellow] {e}")
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
        console.print("[bold green][+] Starting WiFi_Sniffer"); time.sleep(1)


        Background_Threads.channel_hopper(iface=iface)

        WiFi_Sniffer._wifi_scan(iface=iface)

        console.print(f"[bold red][-] Killed -->[bold yellow] WiFi_Sniffer")



# OUTDATED
class Recon_Pusher():
    """This class will be used to push data from recon mode"""



    @classmethod
    def push_results(cls, devices:any, verbose=True) -> None:
        """This will save ble wardriving results"""
        

        with LOCK:

            data  = {}
            num = 0
            macs = []

            file_saving = Variables.file_saving

            if not file_saving: return False
            


            path = Path(__file__).parent.parent / "database" 


            try:

                drive = path / "database.json"


                if drive.exists():

                    with open(drive, "r") as file: data = json.load(file)

                    for _, value in data.items(): macs.append(value["addr"]); num+=1

                for _, device in devices.items(): 

                    if device["addr"] not in macs:

                        num += 1; macs.append(device["addr"]); data[num] = device
            

                with open(drive, "w") as file: json.dump(data, file, indent=4)
                if verbose: console.print("[bold green][+] Wardrive pushed!")


            except json.JSONDecodeError as e:
                console.print(f"[bold red][!] JSON Error:[bold yellow] {e}")
                with open(drive, "w") as file: json.dump(data, file, indent=4)
                console.print("[bold green][+] json file created!")

                        
            except Exception as e: console.print(f"[bold red][!] Exception Error:[bold yellow] {e}")

        




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

        if pkt.haslayer(RadioTap):
            
            rssi = getattr(pkt, "dBm_AntSignal", False)
            
            if rssi:

                if format:
                    return f"{rssi} dBm"
                
                return rssi


    @classmethod
    def get_encryption(cls, pkt):
        """Get this encryption"""

        if pkt.haslayer(Dot11Beacon):

            cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}")

            if pkt.haslayer(Dot11Elt):
                elt = pkt[Dot11Elt]
                while isinstance(elt, Dot11Elt):

                    if elt.ID == 48:
                        rsn_info = elt.info
        
                        if b'\x00\x0f\xac\x08' in rsn_info: return "WPA3"
                        else: return "WPA2"

                    elif elt.ID == 221 and len(elt.info) >= 4 and elt.info[:4] == b'\x00\x50\xf2\x01':  return "WPA"
                    elt = elt.payload

            if "privacy" in cap.lower(): return "WEP"
            else: return "Open"

        return None
