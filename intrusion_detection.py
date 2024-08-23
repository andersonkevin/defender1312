import time
from scapy.all import sniff, IP, Ether
from utils import log_event

def detect_intrusion(monitor_time=300, devices=None):
    if devices is None:
        devices = defaultdict(lambda: {'name': '', 'mac': ''})
    print(f"Monitoring network traffic for {monitor_time} seconds. Press Ctrl-C to exit.")
    start_time = time.time()
    suspicious_devices = []
    try:
        while (time.time() - start_time) < monitor_time:
            sniff(prn=lambda x: process_packet(x, devices, suspicious_devices), timeout=10)
        classify_devices(devices, suspicious_devices)
    except KeyboardInterrupt:
        print("Exiting...")
        sys.exit(0)

def process_packet(packet, devices, suspicious_devices):
    if packet.haslayer(IP) and packet.haslayer(Ether):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        mac_src = packet[Ether].src
        mac_dst = packet[Ether].dst

        if mac_src not in devices:
            devices[mac_src] = {'ip': ip_src, 'last_seen': time.time(), 'status': 'safe'}
        else:
            devices[mac_src]['last_seen'] = time.time()

        if mac_dst not in devices:
            devices[mac_dst] = {'ip': ip_dst, 'last_seen': time.time(), 'status': 'safe'}
        else:
            devices[mac_dst]['last_seen'] = time.time()

        if mac_src in suspicious_devices or mac_dst in suspicious_devices:
            log_event(f"Suspicious packet detected from {mac_src} to {mac_dst}: {repr(packet)}")
            devices[mac_src]['status'] = 'suspicious'
            devices[mac_dst]['status'] = 'suspicious'

def classify_devices(devices, suspicious_devices):
    for ip_address, device_info in devices.items():
        if ip_address in suspicious_devices:
            device_info['status'] = 'suspicious'
        else:
            device_info['status'] = 'safe'
