import nmap
import scapy.all as scapy
from collections import defaultdict
from utils import log_error
import os

# Sample OUI mapping for device type detection
OUI_MAPPING = {
    "ac:3b:77": "Apple Inc.",
    "50:ed:3c": "Samsung Electronics",
    "aa:a2:d1": "Cisco Systems",
    "b2:1c:fc": "Dell Inc.",
    # Add more OUI mappings here...
}

# Custom names for known devices
KNOWN_DEVICES = {
    "ac:3b:77:8c:a4:b4": "Router",
    "50:ed:3c:17:74:98": "Kevin's Smartphone",
    "aa:a2:d1:df:e1:67": "Smart TV",
    # Add more known devices here...
}

def get_device_type(mac_address):
    """Returns the device type based on OUI or a custom name."""
    mac_prefix = mac_address[:8].lower()
    return KNOWN_DEVICES.get(mac_address.lower(), OUI_MAPPING.get(mac_prefix, "Unknown Device"))

def scan_network(ip_range="192.168.1.0/24"):
    """Scans the given IP range and returns a dictionary of detected devices."""
    devices = defaultdict(lambda: {'name': '', 'mac': '', 'type': ''})
    try:
        ans, unans = scapy.arping(ip_range, timeout=2, verbose=False)
        for s, r in ans.res:
            mac_address = r.hwsrc.lower()
            device_type = get_device_type(mac_address)
            devices[r.psrc] = {
                'mac': mac_address,
                'type': device_type,
                'name': KNOWN_DEVICES.get(mac_address, "Unknown Device")
            }
    except PermissionError as e:
        log_error(f"Permission denied during network scan: {e}. Try running with sudo.")
    except Exception as e:
        log_error(f"Error during network scan: {e}")
    return devices

def check_ports(ip, port_range="1-1024"):
    """Checks for open ports on a device."""
    nm = nmap.PortScanner()
    nm.scan(ip, arguments=f'-p {port_range} -sT')
    open_ports = set()
    try:
        if 'tcp' in nm[ip]:
            open_ports = {f"{port}/{nm[ip]['tcp'][port]['name']}" for port in nm[ip]['tcp'] if nm[ip]['tcp'][port]['state'] == 'open'}
    except KeyError:
        log_error(f"No open ports found on {ip}")
    return open_ports

def classify_devices(devices):
    """Classifies devices based on open ports."""
    for ip, info in devices.items():
        open_ports = check_ports(ip)
        if "22/tcp" in open_ports:
            info["status"] = "dangerous"
        elif "80/tcp" in open_ports:
            info["status"] = "warning"
        else:
            info["status"] = "safe"
    return devices

def get_connected_devices():
    """Retrieves devices connected to the Wi-Fi network."""
    # This function will differ based on the OS and router type.
    # On macOS, you can use the 'airport' command, but this requires sudo.
    connected_devices = {}
    
    if os.name == 'posix':
        # Example using `arp` command on macOS/Linux
        output = os.popen("arp -a").read()
        for line in output.splitlines():
            if "at" in line:
                parts = line.split()
                ip = parts[1].strip("()")
                mac = parts[3]
                connected_devices[ip] = mac
    elif os.name == 'nt':
        # Example using `arp -a` command on Windows
        output = os.popen("arp -a").read()
        for line in output.splitlines():
            if "-" in line:
                parts = line.split()
                ip = parts[0]
                mac = parts[1]
                connected_devices[ip] = mac
    
    # Label devices by checking against KNOWN_DEVICES or OUI_MAPPING
    labeled_devices = {}
    for ip, mac in connected_devices.items():
        labeled_devices[ip] = {
            'mac': mac,
            'type': get_device_type(mac),
            'name': KNOWN_DEVICES.get(mac.lower(), "Unknown Device")
        }
    
    return labeled_devices