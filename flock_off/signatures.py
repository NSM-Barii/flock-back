# signatures.py
# THIS FILE WILL HOLD MAC INFO FOR FLOCK AND OTHER TYPES OF SIMILAR DEVICES


# Raven Device Information Service (used across all firmware versions)
RAVEN_DEVICE_INFO_SERVICE = "0000180a-0000-1000-8000-00805f9b34fb"

# Raven GPS Location Service (firmware 1.2.0+)
RAVEN_GPS_SERVICE = "00003100-0000-1000-8000-00805f9b34fb"

# Raven Power/Battery Service (firmware 1.2.0+)
RAVEN_POWER_SERVICE = "00003200-0000-1000-8000-00805f9b34fb"

# Raven Network Status Service (firmware 1.2.0+)
RAVEN_NETWORK_SERVICE = "00003300-0000-1000-8000-00805f9b34fb"

# Raven Upload Statistics Service (firmware 1.2.0+)
RAVEN_UPLOAD_SERVICE = "00003400-0000-1000-8000-00805f9b34fb"

# Raven Error/Failure Service (firmware 1.2.0+)
RAVEN_ERROR_SERVICE = "00003500-0000-1000-8000-00805f9b34fb"

# Health Thermometer Service (firmware 1.1.7)
RAVEN_OLD_HEALTH_SERVICE = "00001809-0000-1000-8000-00805f9b34fb"

# Location and Navigation Service (firmware 1.1.7)
RAVEN_OLD_LOCATION_SERVICE = "00001819-0000-1000-8000-00805f9b34fb"


FLOCK_SIGNATURES = {
    "wifi_ssid_patterns": [
        "flock",        # Standard Flock Safety naming
        "Flock",        # Capitalized variant
        "FLOCK",        # All caps variant
        "FS Ext Battery", # Flock Safety Extended Battery devices
        "Penguin",      # Penguin surveillance devices
        "Pigvision"     # Pigvision surveillance systems
    ],

    "mac_prefixes": [
        # FS Ext Battery devices
        "58:8e:81", "cc:cc:cc", "ec:1b:bd", "90:35:ea", "04:0d:84", 
        "f0:82:c0", "1c:34:f1", "38:5b:44", "94:34:69", "b4:e3:f9",
    
        # Flock WiFi devices
        "70:c9:4e", "3c:91:80", "d8:f3:bc", "80:30:49", "14:5a:fc",
        "74:4c:a1", "08:3a:88", "9c:2f:9d", "94:08:53", "e4:aa:ea"
    ],

    "ble_name_patterns": [
        "FS Ext Battery",  # Flock Safety Extended Battery
        "Penguin",         # Penguin surveillance devices
        "Flock",           # Standard Flock Safety devices
        "Pigvision"        # Pigvision surveillance systems
    ],

    
    # Known Raven service UUIDs for detection
    "raven_service_uuids": [
        RAVEN_DEVICE_INFO_SERVICE,  # Device info (all versions)
        RAVEN_GPS_SERVICE,          # GPS data (1.2.0+)
        RAVEN_POWER_SERVICE,        # Battery/Solar (1.2.0+)
        RAVEN_NETWORK_SERVICE,      # LTE/WiFi status (1.2.0+)
        RAVEN_UPLOAD_SERVICE,       # Upload stats (1.2.0+)
        RAVEN_ERROR_SERVICE,        # Error tracking (1.2.0+)
        RAVEN_OLD_HEALTH_SERVICE,   # Old health service (1.1.7)
        RAVEN_OLD_LOCATION_SERVICE  # Old location service (1.1.7)
    ]

}
