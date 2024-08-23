import click
import netifaces
import logging
import ipaddress
from network_scanner import scan_network, classify_devices, get_connected_devices
from intrusion_detection import detect_intrusion
from utils import setup_logging

def list_available_ips():
    """Lists all available IP addresses on the system's network interfaces."""
    print("\nAvailable IP addresses:")
    for interface in netifaces.interfaces():
        addresses = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addresses:
            for link in addresses[netifaces.AF_INET]:
                ip = link.get('addr', 'N/A')
                if ip.startswith('127.'):
                    label = 'Localhost (Loopback)'
                elif ip.startswith('192.') or ip.startswith('10.') or ip.startswith('172.'):
                    label = 'Private (Local Network)'
                else:
                    label = 'Public'
                print(f"Interface: {interface} | IP: {ip} | Label: {label}")

def validate_ip_range(ip_range):
    """Validates and returns a proper CIDR range."""
    try:
        ip_net = ipaddress.ip_network(ip_range, strict=False)
        return str(ip_net)
    except ValueError:
        raise click.BadParameter(f"{ip_range} is not a valid CIDR range or IP address.")

@click.command()
def main():
    setup_logging()
    click.echo("DEFENDER 0.0.2 - Cyber Defense Tool")
    
    # List available IPs before asking for an IP range
    list_available_ips()

    # Optionally get connected devices on Wi-Fi network
    wifi_devices = get_connected_devices()
    if wifi_devices:
        click.echo("\nConnected Wi-Fi Devices:")
        for ip, info in wifi_devices.items():
            click.echo(f"IP Address: {ip}, MAC Address: {info['mac']}, Type: {info['type']}, Name: {info['name']}")

    if not click.confirm("This script will scan your network and detect potential intruders. Do you want to continue?", default=True):
        click.echo("Exiting...")
        return

    ip_range = click.prompt("Enter the IP range to scan (e.g., 192.168.1.0/24)", default="192.168.1.0/24")
    ip_range = validate_ip_range(ip_range)
    
    click.echo(f"\nScanning network {ip_range}...")
    devices = scan_network(ip_range)
    click.echo(f"\n{len(devices)} devices found on the network.")
    
    if devices:
        click.echo("\nDetected Devices:")
        for ip, info in devices.items():
            click.echo(f"IP Address: {ip}, MAC Address: {info['mac']}, Type: {info.get('type', 'Unknown')}, Name: {info['name']}")
    
    # Classify devices based on open ports and known vulnerabilities
    devices = classify_devices(devices)
    
    monitor_time = click.prompt("How many minutes do you want to monitor the network?", default=5, type=int)
    click.echo(f"\nMonitoring network traffic for {monitor_time} minute(s). Press Ctrl-C to exit.")
    
    try:
        detect_intrusion(monitor_time=monitor_time * 60, devices=devices)
    except KeyboardInterrupt:
        click.echo("\nMonitoring interrupted. Exiting...")
        return
    
    click.echo("\nMonitoring complete.")
    print_final_report(devices)

def print_final_report(devices):
    """Prints a summary report of the scanned devices."""
    dangerous_devices = [d for d in devices.values() if d['status'] == 'dangerous']
    suspicious_devices = [d for d in devices.values() if d['status'] == 'suspicious']
    
    click.echo("\nFinal Report:")
    click.echo(f"Total devices found: {len(devices)}")
    click.echo(f"Dangerous devices: {len(dangerous_devices)}")
    click.echo(f"Suspicious devices: {len(suspicious_devices)}")
    
    if dangerous_devices or suspicious_devices:
        click.echo("\nRecommended Actions:")
        for device in dangerous_devices:
            click.echo(f"Dangerous device found: {device['mac']} (IP: {device['ip']}) - Take immediate action!")
        for device in suspicious_devices:
            click.echo(f"Suspicious device found: {device['mac']} (IP: {device['ip']}) - Monitor closely.")
    else:
        click.echo("Your network appears to be safe.")

if __name__ == "__main__":
    main()
