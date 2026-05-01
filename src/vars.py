# THIS WILL BE USED TO HOUSE MODULE WIDE VARIABLES



# IMPORTS
import threading
from rich.console import Console




class Variables():
    """This will house program wide variables"""


    bface    = "hci0"
    iface   = False
    gps     = False
    help    = False
    packet  = False
    verbose = False


    BACKGROUND = True
    ai_cameras_all = {
        "wifi": [],
        "ble": []
    }

    wifi_ai_cameras = []
    ble_ai_cameras = []
    

    LOCK = threading.RLock()
    console = Console()
    verbose = False