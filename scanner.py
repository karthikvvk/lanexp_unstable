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
        # lis = scanfromlinux().append("10.150.130.23")
        lis = ["10.150.130.23"]
        return lis
    elif system_name.startswith("win") or system_name.startswith("nt"):
        return scanfromwin()
    else:
        print(f"[!] Unsupported system: {system_name}")
        return []











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
        # Validate network by constructing IPv4Network
        IPv4Network(network, strict=False)
    except Exception as e:
        print(f"[!] Invalid network from GATEWAY/CIDR: {e}", file=os.sys.stderr)
        return []

    # Methods to try in order
    methods = [
        ("nmap_unprivileged", _scan_nmap_unprivileged),
        ("arp_neigh", _scan_arp_table),
        ("ping_sweep", _scan_ping_sweep),
    ]

    for name, func in methods:
        try:
            found = func(network)
            if found:
                # update file and return the list
                append_host(found)
                return found
        except Exception as e:
            # keep trying other methods on any failure
            print(f"[!] {name} failed: {e}", file=os.sys.stderr)
            continue

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
            return ip if res.returncode == 0 else None
        except Exception:
            return None

    alive = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=200) as ex:
        for r in ex.map(ping_check, ip_list):
            if r:
                alive.append(r)
    return sorted(alive)










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
        total_ips = existing_ips.union(set(lis))
        
        # Write back sorted list
        with open(file_path, "w") as fh:
            for ip in sorted(total_ips, key=lambda x: [int(p) for p in x.split('.')]):
                fh.write(ip + "\n")
        
        print(f"[+] Updated {file_path} with {len(total_ips)} total hosts")
        
    except Exception as e:
        print(f"[!] Error updating host list: {e}")


# print(gethostlist())