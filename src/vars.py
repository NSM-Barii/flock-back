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
    delay   = 0.125
    hops    = [1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161]

    presets = {
        "2.4": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
        "5":   [36, 40, 44, 48, 149, 153, 157, 161],
        "all": [1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161]
    }


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