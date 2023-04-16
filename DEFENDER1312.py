# Standard library imports
import os
import sys
import platform
import socket
import time
import socket
import multiprocessing
import random
import socket
import struct
import port_scanner
import nmap
import asyncio
import ipaddress
import argparse
from port_scanner import scan_ports
from typing import List, Dict
from tqdm import tqdm
from rich.console import Console
from rich.progress import Progress
from collections import defaultdict

# Third-party imports
import click
import nmap
import scapy.all
from scapy.all import ARP, Ether, IP, TCP, srp, sr1
from netifaces import interfaces, ifaddresses, AF_INET

def get_hosts_from_subnet(subnet, mask=24):
    net = ipaddress.IPv4Network(subnet, strict=False)
    hosts = [str(ip) for ip in net.hosts()]
    return hosts


def get_ip_address():
    """Gets the IP address of the local machine."""
    for ifaceName in interfaces():
        addresses = ifaddresses(ifaceName)
        if AF_INET in addresses:
            for address in addresses[AF_INET]:
                if 'addr' in address:
                    return address['addr']
    return None


def scan_network(ip_range="192.168.1.0/24"):
    devices = defaultdict(lambda: {'name': '', 'mac': '', 'type': ''})
    try:
        ans, unans = scapy.all.arping(ip_range, timeout=2, verbose=False)
        for s, r in ans.res:
            devices[r.psrc]['mac'] = r.hwsrc
            # send an additional packet to obtain more information about the device
            # for example, a DHCP request packet to see if the device is assigned an IP address by a DHCP server
            dhcp_request = scapy.all.Ether(dst='ff:ff:ff:ff:ff:ff')/scapy.all.IP(src='0.0.0.0',dst='255.255.255.255')/scapy.all.UDP(sport=68,dport=67)/scapy.all.BOOTP(chaddr=r.hwsrc)/scapy.all.DHCP(options=[('message-type','request'),('param_req_list', b'\x01\x03\x06\x0f\x1f\x21\x2b\x2c\x2e\x2f\x79\x7a\x7b\x7c'), 'end'])
            resp = scapy.all.srp(dhcp_request, iface_hint=r.psrc, timeout=1, verbose=False)
            if resp and resp[0] and resp[0][1]:
                dhcp_options = resp[0][1][scapy.all.DHCP].options
                # check if the device is assigned an IP address by a DHCP server
                if any('requested_addr' in option for option in dhcp_options):
                    devices[r.psrc]['type'] = 'DHCP'
                # you can add more checks here to obtain more information about the device type
                # for example, by analyzing the responses to TCP or UDP packets sent to specific ports
    except:
        pass
    return devices


def check_single_port(target, port, timeout=1):
    """
    Check if a single port on a host is open.
    Returns True if the port is open, False otherwise.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            return True
        else:
            return False

async def check_ports(host, port_range):
    open_ports = []
    try:
        for port in range(port_range[0], port_range[1]+1):
            conn = asyncio.open_connection(host, port)
            await asyncio.wait_for(conn, timeout=0.5)
            open_ports.append(port)
            conn.close()
    except asyncio.TimeoutError:
        pass
    except Exception as e:
        print(f"Error checking port {port}: {e}")
    return open_ports

async def check_host(host: str, port_range: str) -> Dict[int, bool]:
    """
    Scans a single host on multiple ports.
    Returns a dictionary of open ports.
    """
    open_ports = {}
    for port in range(*parse_port_range(port_range)):
        if await check_port(host, port):
            open_ports[port] = True
        else:
            open_ports[port] = False
    return open_ports

async def check_hosts(target_hosts, port_range):
    tasks = []
    for host in target_hosts:
        tasks.append(check_ports(host, port_range))
    results = await asyncio.gather(*tasks)
    return results


if __name__ == '__main__':
    host = 'localhost'
    ports = [22, 80, 443, 8080, 9000]
    open_ports = check_ports(host, ports)
    if open_ports:
        print(f'The following ports are open on {host}: {open_ports}')
    else:
        print(f'No open ports found on {host}.')

def scan_ports(target, port_range, timeout=2):
    """
    Scan a range of ports on a target host.

    :param target: A string representing the target host IP address.
    :param port_range: A tuple containing the start and end ports of the range to scan.
    :param timeout: The timeout value for each port scan in seconds (default is 2 seconds).
    :return: A list of open ports.
    """
    open_ports = []

    # Loop through the range of ports and check each one
    for port in range(port_range[0], port_range[1]+1):
        if check_single_port(target, port, timeout=timeout):
            open_ports.append(port)

    return open_ports

async def check_all_hosts(hosts, port_range):
    for host in hosts:
        await check_ports(host, port_range)

async def check_port(ip, port):
    conn = asyncio.open_connection(ip, port)
    try:
        reader, writer = await asyncio.wait_for(conn, timeout=1)
        writer.close()
        await writer.wait_closed()
        return port, True
    except Exception as e:
        return port, False

async def scan_ports(ip, port_range):
    start_port, end_port = port_range
    tasks = [check_port(ip, port) for port in range(start_port, end_port+1)]
    results = await asyncio.gather(*tasks)
    open_ports = [p for p, success in results if success]
    return open_ports

async def main():
    target_hosts = []
    while True:
        target_host = input("Enter target IP address: ")
        if not target_host:
            break
        target_hosts.append(target_host)
    port_range = input("Enter port range (start:end): ")
    results = await check_hosts(target_hosts, port_range)
    for result in results:
        print_open_ports(result)


if __name__ == "__main__":
    asyncio.run(main())

# Define a function to check multiple ports on a single host
def check_multiple_ports(host:str, ports:List[int], timeout:int=2) -> Dict[int, bool]:
    """
    Checks multiple ports on a single host.
    Returns a dictionary with port numbers as keys and booleans as values.
    """
    results = {}  # Initialize an empty dictionary to store the results
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)  # Set the socket timeout
            try:
                s.connect((host, port))  # Attempt to connect to the host and port
                results[port] = True  # If successful, mark the port as open
            except:
                results[port] = False  # If unsuccessful, mark the port as closed
    return results  # Return the dictionary of results


# Define a function to scan multiple hosts on multiple ports
def check_hosts(hosts:List[str], ports:List[int], timeout:int=2) -> Dict[str, Dict[int, bool]]:
    """
    Scans multiple hosts on multiple ports.
    Returns a dictionary of hosts with a nested dictionary of open ports.
    """
    results = {}  # Initialize an empty dictionary to store the results
    for host in hosts:
        results[host] = check_multiple_ports(host, ports, timeout)  # Check the ports on the current host
    return results  # Return the dictionary of results


def main():
    target = input("Enter target IP address: ")
    port_range = tuple(map(int, input("Enter port range (start:end): ").split(":")))
    open_ports = scan_ports(target, port_range)
    if open_ports:
        print("Open ports:", open_ports)
    else:
        print("No open ports found.")
    
if __name__ == '__main__':
    main()

def scan(target, ports):
    print('\n' + 'Starting scan on host ' + target)
    for port in ports:
        check_single_port(target, port)

    # Check if the remote host is alive
    response = os.system("ping -c 1 " + hostname)

    if response == 0:
        print(hostname, 'is up!')
        # Check the status of the ports
        for port in ports:
            check_port(hostname, port)
    else:
        print(hostname, 'is down!')

def check_hosts(target_hosts:List[str]):
    for host in target_hosts:
        check_host(host)

def main():
    # get target IP address and port range from user input
    target_ip = input("Enter target IP address: ")
    port_range = tuple(map(int, input("Enter port range (start:end): ").split(":")))
    
    # scan ports on target IP address
    open_ports = scan_ports(target_ip, port_range)
    if open_ports:
        print(f"Open ports on {target_ip}: {open_ports}")
    else:
        print(f"No open ports found on {target_ip}")

    # scan ports on multiple hosts
    target_hosts = get_hosts_from_subnet(target_ip)
    if target_hosts:
        check_hosts(target_hosts)
    else:
        print(f"No hosts found on subnet of {target_ip}")

if __name__ == "__main__":
    main()

# Run the function for each host in the list
for host in target_host:
    check_host(host)

def scan_port_range(host, start_port, end_port):
    """
    Scan a range of ports on a specified host using threads and check if they are open
    :param host: str - IP address or hostname of the target host
    :param start_port: int - starting port number of the range to be scanned
    :param end_port: int - ending port number of the range to be scanned
    :return: list of open ports
    """
    open_ports = []
    threads = []
    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=check_single_port, args=(host, port, open_ports))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    return open_ports

# example usage
if __name__ == "__main__":
    host = "localhost"
    start_port = 1
    end_port = 1024
    open_ports = scan_port_range(host, start_port, end_port)
    print(f"Open ports on {host}: {open_ports}")

def port_scan(target, ports, timeout):
    """
    Scans the specified ports on the target and returns a dictionary containing
    the results.
    """
    print(f"Scanning ports on {target}...")
    results = {"open": [], "closed": [], "filtered": []}

    # create a socket object for each port to be scanned
    sockets = []
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        sockets.append(s)

    # scan each port and store the results in the dictionary
    for i in range(len(ports)):
        port = ports[i]
        s = sockets[i]

        # try to connect to the port
        try:
            s.connect((target, port))
            results["open"].append(port)
        except socket.timeout:
            results["filtered"].append(port)
        except:
            results["closed"].append(port)

        # close the socket
        s.close()

    # print the results
    print(f"Results for {target}:")
    print(f"  Open ports: {results['open']}")
    print(f"  Closed ports: {results['closed']}")
    print(f"  Filtered ports: {results['filtered']}")
    
    return results

# Check open ports on the target
def check_open_ports(target, port_list):
    open_ports = []
    for port in port_list:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)  # Set timeout to 0.5 seconds
        result = sock.connect_ex((target, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

# Scan the target for open ports
def port_scan(target):
    # Define a list of commonly used ports to scan
    port_list = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
    print(f"Scanning {target} for open ports...")
    open_ports = check_open_ports(target, port_list)
    if open_ports:
        print(f"{len(open_ports)} open ports found: {open_ports}")
    else:
        print("No open ports found on the target.")

def main():
    args = parse_args()

    # Load the targets and ports
    targets = load_targets(args.target)
    ports = parse_ports(args.port)

    # Check if a single port or multiple ports are being scanned
    if len(ports) == 1:
        check_single_port(targets, ports[0])
    else:
        check_multiple_ports(targets, ports)

if __name__ == '__main__':
    main()
    if len(ip_list) == 1:
        print("Scanning single host...")
        check_single_host(ip_list[0], start_port, end_port)
    else:
        print("Scanning multiple hosts...")
        for ip in ip_list:
            t = threading.Thread(target=check_single_host, args=(ip, start_port, end_port))
            threads.append(t)
            t.start()

        # Wait for all threads to finish
        for t in threads:
            t.join()

if __name__ == '__main__':
    main()

def get_device_info(ip, username, password, port=22):
    """
    Function that returns information about a device given its IP address and login credentials.
    :param ip: string, IP address of device to be queried
    :param username: string, username for login
    :param password: string, password for login
    :param port: int, SSH port number (default is 22)
    :return: dictionary containing device information
    """
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, port=port, username=username, password=password, timeout=10)
        stdin, stdout, stderr = client.exec_command('show version')
        output = stdout.read()
        client.close()
    except Exception as e:
        print(f"Error connecting to {ip}: {str(e)}")
        return None

    try:
        device_info = {}
        device_info['hostname'] = get_hostname(output)
        device_info['serial'] = get_serial_number(output)
        device_info['model'] = get_model(output)
        device_info['ios_version'] = get_ios_version(output)
        device_info['uptime'] = get_uptime(output)
        device_info['interfaces'] = get_interfaces(ip, username, password, port)
        device_info['routes'] = get_routing_table(ip, username, password, port)
        device_info['neighbors'] = get_cdp_neighbors(ip, username, password, port)
        device_info['arp_table'] = get_arp_table(ip, username, password, port)
        return device_info
    except Exception as e:
        print(f"Error getting information from {ip}: {str(e)}")
        return None
# Handle the case where the input file is empty
if not all_lines:
    print("No hosts found in the input file")
    exit(1)

# Create the output file if it doesn't exist
if not os.path.exists(output_file):
    open(output_file, "w").close()

# Write the output to the file
with open(output_file, "w") as f:
    f.write("\n".join(output_lines))

print("Done! Results have been written to", output_file)

# if a response is not received within timeout seconds, consider it a failure
def receive_data(sock, timeout):
    sock.settimeout(timeout)
    try:
        data = sock.recv(1024).decode()
        return data
    except socket.timeout:
        return None


# function to send a command and receive its response
def send_command(sock, cmd, timeout=2):
    # send the command
    sock.sendall(cmd.encode())

    # receive the response
    response = receive_data(sock, timeout)

    # check if the response is empty
    if not response:
        print("No response received from the device.")
        return None

    # check if the response is an error message
    if "ERROR" in response:
        print(f"Error received: {response}")
        return None

    # return the response
    return response

# main function that executes the port scan
def port_scan(target_ip, target_ports, timeout):
    # create a socket object
    scanner_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # set the default timeout for the socket
    scanner_socket.settimeout(timeout)
    # set a variable to store the open ports
    open_ports = []
    # scan through each port in the list of target ports
    for port in target_ports:
        # check if the port is open
        if check_single_port(scanner_socket, target_ip, port):
            # if the port is open, add it to the list of open ports
            open_ports.append(port)
    # close the socket
    scanner_socket.close()
    # return the list of open ports
    return open_ports

# main function to execute the port scan and print the results
def main():
    # get the target IP address
    target_ip = input("Enter the target IP address: ")
    # get the range of ports to scan
    port_range = input("Enter the range of ports to scan (e.g. 1-100): ")
    # convert the port range string into a list of integers
    start_port, end_port = map(int, port_range.split('-'))
    target_ports = range(start_port, end_port+1)
    # set the timeout for the scanner socket
    timeout = 1
    # execute the port scan
    open_ports = port_scan(target_ip, target_ports, timeout)
    # print the results
    if len(open_ports) == 0:
        print("No open ports found on target.")
    else:
        print("Open ports found on target:")
        for port in open_ports:
            print(f"\tPort {port} is open.")

if __name__ == "__main__":
    main()

# Create the main function to run the script
def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Port scanner')
    parser.add_argument('--ip', help='The IP address to scan', required=True)
    parser.add_argument('--start', help='The starting port', required=True)
    parser.add_argument('--end', help='The ending port', required=True)
    parser.add_argument('--timeout', help='The timeout (in seconds) for the port scan', default=1)
    parser.add_argument('--method', help='The method to use for scanning ports (tcp or udp)', default='tcp')
    args = parser.parse_args()

    # Set the IP address to scan
    target = args.ip

    # Set the start and end ports to scan
    start_port = int(args.start)
    end_port = int(args.end)

    # Set the timeout for the port scan
    timeout = float(args.timeout)

    # Set the method for scanning ports
    method = args.method.lower()

    # Display the target IP address and ports to scan
    print(f'Starting port scan on {target} from port {start_port} to port {end_port} using {method.upper()} method')

    # Scan the ports
    if method == 'tcp':
        open_ports = scan_tcp_ports(target, start_port, end_port, timeout)
    elif method == 'udp':
        open_ports = scan_udp_ports(target, start_port, end_port, timeout)
    else:
        print(f'Invalid method {method}')
        return

    # Display the open ports
    if len(open_ports) == 0:
        print('No open ports found')
    else:
        print('Open ports:')
        for port in open_ports:
            print(port)

# Call the main function
if __name__ == '__main__':
    main()

# code for scanning multiple ports on multiple hosts
def check_host(host:str):
    print(f"Scanning host {host}...")
    open_ports = scan_ports(host, port_range)
    if open_ports:
        print(f"Open ports on {host}: {open_ports}\n")
    else:
        print(f"No open ports found on {host}\n")

if __name__ == "__main__":
    # Get target IP address and port range from user input
    target_ip = input("Enter target IP address: ")
    port_range = tuple(map(int, input("Enter port range (start:end): ").split(":")))

    # Scan ports on target IP address
    open_ports = port_scanner.scan_ports(target_ip, port_range)
    if open_ports:
        print(f"Open ports on {target_ip}: {open_ports}")
    else:
        print(f"No open ports found on {target_ip}")

    # Scan ports on multiple hosts
    target_hosts = port_scanner.get_hosts_from_subnet(target_ip)
    if target_hosts:
        for host in target_hosts:
            port_scanner.check_host(host)
    else:
        print(f"No hosts found on subnet of {target_ip}")
