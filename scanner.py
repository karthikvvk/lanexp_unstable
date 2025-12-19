import getpass
import os
import subprocess
import platform
import re
import threading
from ipaddress import IPv4Network, IPv4Address
import concurrent.futures
from typing import List
from dotenv import load_dotenv
import requests
import socket
import time

# from api_bridge import check_subnet, get_OS_TYPE

# Global variables
host_ip = ""
cidr = ""
gateway = ""
subnet = ""
broadcast = ""
interface = ""
system_name = ""
user = ""
pwd = ""
dest_host = ""
file_path = ""




def check_subnet(ip, host_ip):
    # env = load_env_vars()
    # host_ip = env["host"]
    if not host_ip:
        raise ValueError("HOST environment variable not set")

    ip_parts = ip.strip().split('.')
    default_parts = host_ip.strip().split('.')
    ed = ip_parts[-1]
    
    if ed == '1' or ed == "200" or ed == "255":
        return False
    
    return ip_parts[:-1] == default_parts[:-1]


def get_OS_TYPE(REMOTE_HOST=""):
    try:
        response = requests.post(f"http://{REMOTE_HOST}:5000/osinfo", 
                                json={"request": "osinfo"})
        if response.status_code == 200:
            data = response.json()
            return {"os": data.get("os", "linux"), "user": data.get("user")}
        else:
            return {"os": "linux", "user": None}
    except:
        return {"os": "linux", "user": None}




def load_env():
    """Load environment variables from .env file"""
    global host_ip, cidr, gateway, subnet, broadcast, interface, system_name, user, pwd, dest_host
    
    load_dotenv()
    
    # Load from .env with appropriate defaults
    host_ip = os.getenv("HOST", "")
    cidr = os.getenv("CIDR", "24")
    gateway = os.getenv("GATEWAY", "")
    subnet = os.getenv("SUBNET", "255.255.255.0")
    broadcast = os.getenv("BROADCAST", "")
    interface = os.getenv("INTERFACE", "")
    system_name = os.getenv("SYSTEM", platform.system().lower())
    user = os.getenv("USER", getpass.getuser())
    pwd = os.getenv("PWD", os.getcwd())
    dest_host = os.getenv("DEST_HOST", "")
    
    print(f"[+] Loaded scanner environment variables")
    print(f"    Network: {gateway}/{cidr}")
    print(f"    Interface: {interface}")
    print(f"    System: {system_name}")


def checkfile():
    """Ensure the IP list file exists"""
    global file_path
    if not os.path.exists(file_path):
        open(file_path, "w").close()
        print(f"[+] Created {file_path}")


def gethostlist():
    """Main function to scan network and return list of hosts"""
    global file_path, system_name
    
    load_env()
    
    file_path = os.path.join(pwd, "ipsn.txt")
    
    if system_name.startswith("lin"):
        # return scanfromlinux()
        host_list = scanfromlinux()#.append("10.150.130.23")
        # lis = ["10.150.130.23"]
    elif system_name.startswith("win") or system_name.startswith("nt"):
        host_list = scanfromwin()
    
    result = []
    for ip in host_list:
        subck = check_subnet(ip, host_ip)
        if subck:
            res = get_OS_TYPE(ip)
            username = res.get("user")
            if username:
                result.append({"host": ip, "user": username, "os": res.get("os", "linux")})
    return result
    












def scan_udp(network=None):
    """
    Scans for UDP discovery agents (CA/Peers) by broadcasting WHO_IS_CA.
    """
    network  = f"{gateway}/{cidr}"
    global broadcast
    DISCOVERY_PORT = 4434
    DISCOVERY_MSG = b"WHO_IS_CA"
    CA_RESPONSE_PREFIX = b"I_AM_CA"
    
    found = set()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(2.0)
        
        # Send broadcast to generic 255.255.255.255
        try:
            sock.sendto(DISCOVERY_MSG, ('<broadcast>', DISCOVERY_PORT))
        except Exception as e:
            # print(f"[!] Generic broadcast failed: {e}")
            pass
            
        # Also try directed broadcast if available
        if broadcast:
             try:
                 sock.sendto(DISCOVERY_MSG, (broadcast, DISCOVERY_PORT))
             except Exception:
                 pass
        
        start_time = time.time()
        while time.time() - start_time < 2.0:
            try:
                data, addr = sock.recvfrom(4096)
                if data.startswith(CA_RESPONSE_PREFIX):
                    found.add(addr[0])
            except socket.timeout:
                break
            except Exception:
                pass
        sock.close()
    except Exception as e:
        print(f"[!] UDP Scan failed: {e}", file=os.sys.stderr)
        
    return list(found)


def scan_peers_udp(network=None):
    """
    Scans for ANY active peers by broadcasting WHO_IS_PEER.
    This is separate from CA discovery.
    """
    global broadcast
    DISCOVERY_PORT = 4434
    PEER_DISCOVERY_MSG = b"WHO_IS_PEER"
    PEER_RESPONSE_PREFIX = b"I_AM_PEER"
    
    found = set()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(2.0)
        
        # Send broadcast to generic 255.255.255.255
        try:
            sock.sendto(PEER_DISCOVERY_MSG, ('<broadcast>', DISCOVERY_PORT))
        except Exception as e:
            pass
            
        # Also try directed broadcast if available
        if broadcast:
             try:
                 sock.sendto(PEER_DISCOVERY_MSG, (broadcast, DISCOVERY_PORT))
             except Exception:
                 pass
        
        start_time = time.time()
        while time.time() - start_time < 2.0:
            try:
                data, addr = sock.recvfrom(4096)
                if data.startswith(PEER_RESPONSE_PREFIX):
                    # Format: I_AM_PEER <host_ip>
                    parts = data.decode().split()
                    if len(parts) >= 2:
                        found.add(parts[1])
                    else:
                        found.add(addr[0])
            except socket.timeout:
                break
            except Exception:
                pass
        sock.close()
    except Exception as e:
        print(f"[!] Peer UDP Scan failed: {e}", file=os.sys.stderr)
        
    return list(found)

# ----------------- Linux scanning integration ----------------- #
def scanfromlinux():
    """Scan network using multiple methods on Linux (no sudo required).
    Returns: list of IPs that are up (List[str]) — no extra parsing; uses env values.
    """
    global gateway, cidr, file_path

    checkfile()

    # Validate env values
    if not gateway:
        print("[!] GATEWAY not set in environment (GATEWAY).", file=os.sys.stderr)
        return []
    try:
        network = f"{gateway}/{cidr}"
        # print(network)
        # Validate network by constructing IPv4Network
        IPv4Network(network, strict=False)
    except Exception as e:
        print(f"[!] Invalid network from GATEWAY/CIDR: {e}", file=os.sys.stderr)
        return []

    # Methods to try in order
    methods = [
        ("ping_sweep", _scan_ping_sweep),
        ("arp_neigh", _scan_arp_table),
        ("nmap_unprivileged", _scan_nmap_unprivileged),
        ("udp_broadcast", scan_udp),
    ]
    hostset = set()
    for name, func in methods:
        # print(f"[*] Trying method: {name}...")
        try:
            found = func(network)
            if found:
                # update file and return the list
                hostset.update(found)
            
                # return found
        except Exception as e:
            # keep trying other methods on any failure
            print(f"[!] {name} failed: {e}", file=os.sys.stderr)
            continue
    if hostset:
        append_host(hostset)
        return hostset
    # nothing found
    return []


# def scanfromlinux():

#     print("[*] Scanning network using nmap...")
#     """
#     Scan network on Linux using only nmap (no sudo required if nmap is allowed
#     to use TCP connect scan). Returns list of IPs that are up (List[str]).
#     """
#     global gateway, cidr, file_path

#     checkfile()

#     if not gateway:
#         print("[!] GATEWAY not set in environment (GATEWAY).", file=os.sys.stderr)
#         return []

#     try:
#         network = str(gateway) + "/" + str(cidr)
#         _ = IPv4Network(network, strict=False)
#     except Exception as e:
#         print("[!] Invalid network from GATEWAY/CIDR: " + str(e), file=os.sys.stderr)
#         return []

#     try:
#         found_ips = _scan_nmap_unprivileged(network)
#     except Exception as e:
#         print("[!] nmap scan failed: " + str(e), file=os.sys.stderr)
#         return []

#     if not found_ips:
#         print("[*] nmap did not find any hosts")
#         return []

#     append_host(found_ips)
#     return found_ips





def _scan_nmap_unprivileged(network: str, ports: str = "22,80,443,445", timeout: int = 120) -> List[str]:
    """Use nmap -sT (TCP connect) without root. Returns list of IPs (strings)."""
    try:
        # check nmap exists
        try:
            subprocess.run(["nmap", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            # nmap not installed
            return []

        args = ["nmap", "-Pn", "-sT", "-p", ports, "-T4", "--open", network]

        # Run with a timeout to avoid hanging
        result = subprocess.check_output(args, text=True, stderr=subprocess.STDOUT, timeout=timeout)
        # print("[*] nmap scan completed", result)
        found = re.findall(r'Nmap scan report for (\d{1,3}(?:\.\d{1,3}){3})', result)
        unique = sorted(set(found))
        return unique
    except subprocess.TimeoutExpired:
        return []
    except Exception:
        return []


def _ping_silent_linux(ip: str) -> None:
    """Silent ping to populate ARP/neighbor table on Linux"""
    try:
        subprocess.run(["ping", "-c", "1", "-W", "1", ip],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
    except Exception:
        pass


def _scan_arp_table(network: str) -> List[str]:
    """
    Populate ARP/neighbor table via pinging a subset and then read `ip neigh`.
    Returns list of IPs present in the neighbor table that belong to `network`.
    """
    try:
        net = IPv4Network(network, strict=False)
    except Exception:
        return []

    all_ips = [str(ip) for ip in net]

    # Avoid huge pre-population runs. Limit to 1024 addresses max.
    if len(all_ips) > 1024:
        all_ips = all_ips[:1024]

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        list(ex.map(_ping_silent_linux, all_ips))

    try:
        out = subprocess.check_output(["ip", "neigh"], text=True)
    except Exception:
        return []

    ips = set(re.findall(r'(\d{1,3}(?:\.\d{1,3}){3})', out))
    # print(f"[*] Found {len(ips)} entries in neighbor table")
    filtered = [ip for ip in sorted(ips) if IPv4Address(ip) in net]
    return filtered


def _scan_ping_sweep(network: str) -> List[str]:
    """Parallel ping sweep of the network. Returns list of alive IPs."""
    try:
        net = IPv4Network(network, strict=False)
    except Exception:
        return []

    ip_list = [str(ip) for ip in net]

    # Limit ping sweep size to first 4096 addresses to avoid extremely long runs
    if len(ip_list) > 4096:
        ip_list = ip_list[:4096]

    def ping_check(ip: str):
        try:
            res = subprocess.run(["ping", "-c", "1", "-W", "1", ip],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
            # print(f"[*] Pinging {ip}: {'Alive' if res.returncode == 0 else 'No response'}")
            return ip if res.returncode == 0 else None
        except Exception:
            return None

    alive = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=200) as ex:
        for r in ex.map(ping_check, ip_list):
            if r:
                alive.append(r)
        # print(f"[*] Ping sweep found {alive} alive hosts")
    return alive










def ping_silent(ip):
    """Silent ping for Windows scanning"""
    try:
        subprocess.run(
            ["ping", "-n", "1", "-w", "100", ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except:
        pass


def scanfromwin():
    """Scan network using ping + arp on Windows"""
    global gateway, cidr, file_path
    
    checkfile()
    
    # Calculate network range based on gateway and CIDR
    if cidr == "24":
        # For /24 networks, scan the same subnet as gateway
        base = gateway.rsplit('.', 1)[0] + "."
        start, end = 1, 255
    elif cidr == "16":
        # For /16 networks, might need different approach
        parts = gateway.split('.')
        base = f"{parts[0]}.{parts[1]}."
        # For simplicity, scan current /24 subnet only
        base = gateway.rsplit('.', 1)[0] + "."
        start, end = 1, 255
    else:
        # Default to /24 subnet
        base = gateway.rsplit('.', 1)[0] + "."
        start, end = 1, 255
    
    print(f"[*] Scanning network: {base}0/{cidr}")
    print(f"[*] Pinging {end - start} addresses...")
    
    threads = []
    for i in range(start, end + 1):
        ip = base + str(i)
        thr = threading.Thread(target=ping_silent, args=(ip,))
        threads.append(thr)
    
    # Start all threads
    for thr in threads:
        thr.start()
    
    # Wait for all threads to complete
    for thr in threads:
        thr.join()
    
    print("[*] Ping sweep complete, checking ARP cache...")
    
    # Get ARP table
    try:
        result = subprocess.run(
            ["arp", "-a"], 
            capture_output=True, 
            text=True,
            
        )
        output = result.stdout
        
        # Extract all IPs from ARP output
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', output)
        unique_ips = list(set(ips))
        
        # Filter to only include IPs in our network range
        if cidr == "24":
            unique_ips = [ip for ip in unique_ips if ip.startswith(base)]
        
        print(f"[+] Found {len(unique_ips)} hosts")
        append_host(unique_ips)
        return unique_ips
        
    except subprocess.TimeoutExpired:
        print("[!] ARP command timed out")
        return []
    except Exception as e:
        print(f"[!] Error reading ARP table: {e}")
        return []


def append_host(lis):
    """Append discovered IPs to the host list file"""
    global file_path, pwd
    
    checkfile()
    
    try:
        # Read existing IPs
        with open(file_path, "r") as fh:
            data = fh.readlines()
        
        existing_ips = set(line.strip() for line in data if line.strip())
        
        # Combine with new IPs
        total_ips = existing_ips.union(lis)
        
        # Write back sorted list
        with open(file_path, "w") as fh:
            for ip in sorted(total_ips, key=lambda x: [int(p) for p in x.split('.')]):
                fh.write(ip + "\n")
        
        print(f"[+] Updated {file_path} with {len(total_ips)} total hosts")
        
    except Exception as e:
        print(f"[!] Error updating host list: {e}")


# print(gethostlist())
print(scan_peers_udp())