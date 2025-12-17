import socket, struct
import getpass
import os
import platform
import re, subprocess
from dotenv import set_key, load_dotenv


pwd = os.getcwd()
user = getpass.getuser()
sys = platform.system().lower()

interface = None
subnet = None
broadcast_address = None
gateway = None
host_ip = None
cidr = None
port = 4433
out_dir = pwd
src_dir = pwd
key = os.path.join(pwd, "key.pem")
certi = os.path.join(pwd, "cert.pem")
dest_host = ""
reciv_host = "0.0.0.0"


def detect_interface():
    """
    Detect a suitable network interface:
    - Prefer interfaces with names like eth*, en*, enp*, ens*
    - Fall back to first non-loopback UP interface with an inet addr
    - Ignore obvious virtual/docker interfaces (veth, docker*, br-*, cni0)
    """
    global host_ip, cidr, interface, sys, pwd, user, certi, key, out_dir, src_dir, port, broadcast_address, gateway, subnet, dest_host, reciv_host

    if sys.startswith("linux"):
        # get a compact ip output with addresses on one line per interface
        out = subprocess.check_output(["ip", "-o", "-4", "addr"], text=True).strip()

        if not out:
            raise RuntimeError("No IPv4 addresses found (ip returned empty)")

        candidates = []
        for line in out.splitlines():
            # example line:
            # "2: wlan0    inet 192.168.0.100/24 brd 192.168.0.255 scope global dynamic noprefixroute"
            # extract interface name and ensure 'inet ' present
            m = re.match(r'^\d+:\s+([^:\s]+)\s+inet\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+)', line)
            if not m:
                continue
            name = m.group(1)
            low = name.lower()
            # ignore loopback and obvious virtual/docker/cni/bridge interfaces
            if low in ("lo",) or low.startswith(("veth", "docker", "br-", "cni0", "virbr", "vmnet")):
                continue
            candidates.append(name)

        if not candidates:
            raise RuntimeError("[-] No non-virtual, non-loopback interface with IPv4 address found")

        # preference order (include wireless too)
        prefs = ("eth", "enp", "ens", "en", "wlan", "wl")
        interface = None
        for pref in prefs:
            for c in candidates:
                if c.startswith(pref):
                    interface = c
                    break
            if interface:
                break

        # fallback: first candidate
        if not interface:
            interface = candidates[0]

        if not interface:
            raise Exception("[-] No Ethernet interface found")
        print("[+] Detected interface:", interface)

    elif sys.startswith("win") or sys.startswith("nt"):
        cmd = [
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -ExpandProperty Name"
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="ignore")
        interfaces = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
        for i in interfaces:
            u = i.lower()
            if u.startswith(("eth", "en", "wi", "lan")):
                interface = u
                break
        if not interface and interfaces:
            interface = interfaces[0].lower()
        if not interface:
            raise Exception("[-] No Ethernet interface found")


def get_network_info():
    """Get dynamic network information using only socket module and basic assumptions"""
    global host_ip, cidr, interface, sys, pwd, user, certi, key, out_dir, src_dir, port, broadcast_address, gateway, subnet, dest_host

    # Try to get the IP from a socket (this will work even in many container setups)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        host_ip = s.getsockname()[0]
    except Exception:
        # fallback: try to read from ip command for the detected interface
        try:
            if interface:
                out = subprocess.check_output(["ip", "-o", "addr", "show", interface], text=True)
                # find the inet address like: inet 172.18.0.2/16 brd 172.18.255.255
                m = re.search(r'inet\s+([\d\.]+)/(\d+)\s+brd\s+([\d\.]+)', out)
                if m:
                    host_ip = m.group(1)
                    cidr = m.group(2)
                    broadcast_address = m.group(3)
        except Exception:
            pass
    finally:
        s.close()

    if not host_ip:
        raise Exception("[-] Unable to determine host IP")

    # If cidr wasn't filled from ip output, infer from common private ranges
    if not cidr:
        ip_parts = list(map(int, host_ip.split('.')))
        if ip_parts[0] == 10:
            cidr = "8"
            subnet = "255.0.0.0"
        elif ip_parts[0] == 172 and 16 <= ip_parts[1] <= 31:
            cidr = "16"
            subnet = "255.255.0.0"
        elif ip_parts[0] == 192 and ip_parts[1] == 168:
            cidr = "24"
            subnet = "255.255.255.0"
        else:
            cidr = "24"
            subnet = "255.255.255.0"
    else:
        # convert cidr to subnet mask
        mask_int = (0xFFFFFFFF << (32 - int(cidr))) & 0xFFFFFFFF
        subnet = socket.inet_ntoa(struct.pack("!I", mask_int))

    # numeric conversions to compute network and broadcast/gateway
    ip_int = struct.unpack("!I", socket.inet_aton(host_ip))[0]
    subnet_int = struct.unpack("!I", socket.inet_aton(subnet))[0]
    network_int = ip_int & subnet_int
    broadcast_int = network_int | (~subnet_int & 0xFFFFFFFF)
    gateway_int = network_int + 1

    gateway = socket.inet_ntoa(struct.pack("!I", gateway_int))
    broadcast = socket.inet_ntoa(struct.pack("!I", broadcast_int))

    # set globals
    gateway = gateway
    broadcast_address = broadcast

    # return dict
    return {
        "HOST": host_ip,
        "SUBNET": subnet,
        "CIDR": cidr,
        "GATEWAY": gateway,
        "BROADCAST": broadcast
    }



def load_env_vars():
    """Load environment variables from .env file into global variables"""
    global host_ip, cidr,  interface, sys, pwd, user, certi, key, out_dir, src_dir, port, broadcast_address, gateway, subnet, dest_host, reciv_host
    
    load_dotenv()
    
    # Load basic variables
    pwd = os.getenv("PWD", os.getcwd())
    user = os.getenv("USER", getpass.getuser())
    sys = os.getenv("SYSTEM", platform.system().lower())
    interface = os.getenv("INTERFACE", interface)
    host_ip = os.getenv("HOST", "")
    subnet = os.getenv("SUBNET", "")
    gateway = os.getenv("GATEWAY", "")
    broadcast_address = os.getenv("BROADCAST", "")
    cidr = os.getenv("CIDR", "")
    port = int(os.getenv("PORT", "4433"))
    out_dir = os.getenv("OUTDIR", "")
    src_dir = os.getenv("SRCDIR", "")
    certi = os.getenv("CERTI", "")
    key = os.getenv("KEY", "")
    dest_host = os.getenv("DEST_HOST", "")
    reciv_host = os.getenv("RECIVHOST", "0.0.0.0")
    
    print(f"[+] Loaded environment variables from .env")
    # print({
    #     "host": host_ip,
    #     "port": port,
    #     "certi": certi,
    #     "key": key,
    #     "out_dir": out_dir,
    #     "src": src_dir,
    #     "interface": interface,
    #     "system": sys,
    #     "pwd": pwd,
    #     "user": user,
    #     "subnet": subnet,
    #     "gateway": gateway,
    #     "broadcast": broadcast_address,
    #     "cidr": cidr,
    #     "dest_host": dest_host
    # })
    return {
        "host": host_ip,
        "port": port,
        "certi": certi,
        "key": key,
        "out_dir": out_dir,
        "src_dir": src_dir,
        "interface": interface,
        "system": sys,
        "pwd": pwd,
        "user": user,
        "subnet": subnet,
        "gateway": gateway,
        "broadcast": broadcast_address,
        "cidr": cidr,
        "dest_host": dest_host,
        "recivhost": reciv_host
    }


def update_env():
    global host_ip, cidr,  interface, sys, pwd, user, certi, key, out_dir, src_dir, port, broadcast_address, gateway, subnet, dest_host, reciv_host
    



def write_env():
    global host_ip, cidr,  interface, sys, pwd, user, certi, key, out_dir, src_dir, port, broadcast_address, gateway, subnet, dest_host, reciv_host
    detect_interface()
    ls = os.listdir(pwd)
    if "key.pem" not in ls or "cert.pem" not in ls:
        os.system("""openssl req -x509 -nodes -newkey rsa:2048 -keyout key.pem -out cert.pem  -days 365 -subj "/CN=quic-server.local\"""")
    get_network_info()
    env_vars = {
        "HOST": host_ip,
        "SUBNET": subnet,
        "CIDR": cidr,
        "GATEWAY": gateway,
        "BROADCAST": broadcast_address,
        "PWD": pwd,
        "USER": user,
        "SYSTEM": sys,
        "INTERFACE": interface,
        "PORT": port,
        "OUTDIR": out_dir,
        "SRCDIR": src_dir,
        "CERTI": certi,
        "KEY": key,
        "DEST_HOST": dest_host,
        "RECIVHOST": reciv_host

    }

    env_file = ".env"
    load_dotenv(env_file)
    if not os.path.exists(env_file):
        open(env_file, "a").close()

    for key, value in env_vars.items():
        set_key(env_file, key, str(value))

    print(f"\n[+] Environment variables updated in {env_file}")


    print(f"\n[+] Environment variables updated in {env_file}")


def setup_pki_and_write_env():
    """Discover/Become CA and setup certificates before writing env"""
    import asyncio
    from pki.ca_service import CAManager
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    print("[*] Starting P2P CA Discovery process...")
    
    # Reload basics to get PWD
    global pwd, out_dir
    load_dotenv()
    pwd = os.getenv("PWD", os.getcwd())
    
    # 1. Ensure keys exist or generate temporary identity for CSR
    key_file = os.path.join(pwd, "key.pem")
    cert_file = os.path.join(pwd, "cert.pem")
    ca_cert_file = os.path.join(pwd, "ca_cert.pem")
    
    if not os.path.exists(key_file):
        print("    Generating new private key...")
        priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(key_file, "wb") as f:
            f.write(priv_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
    
    with open(key_file, "rb") as f:
        priv_key_pem = f.read()

    # 2. Start CA Manager
    # We use '0.0.0.0' for binding but need real IP for advertising if we become CA
    detect_interface()
    get_network_info()
    ca_mgr = CAManager(host_ip, pwd) # host_ip global from get_network_info

    async def run_discovery_flow():
        await ca_mgr.start_discovery()
        
        # Wait for CA for 5 seconds
        print("    Broadcasting 'WHO_IS_CA'...")
        try:
            await asyncio.wait_for(ca_mgr.ca_found_event.wait(), timeout=5.0)
            print(f"    [+] Found CA at {ca_mgr.ca_info}")
            
            # Request Signing
            print("    Requesting certificate signature...")
            client_cert, ca_cert = await ca_mgr.get_signed_cert(priv_key_pem, f"{user}@{host_ip}")
            
            with open(cert_file, "wb") as f:
                f.write(client_cert)
            with open(ca_cert_file, "wb") as f:
                f.write(ca_cert)
            print("    [+] Received signed certificate & CA cert.")
            
        except asyncio.TimeoutError:
            print("    [-] No CA found. Becoming Root CA...")
            await ca_mgr.become_ca()
            # In becoming CA, it writes ca_cert.pem and ca_key.pem to pwd
            # It also starts the signing server. 
            # We need to self-sign our own cert as client too using the CA logic
            # OR just use CA cert as client cert? Standard is separate.
            # Let's request from ourselves (since server is running) or just generate.
            # Simpler: Request from ourselves via loopback or direct call?
            # Direct call is cleaner but let's use the public API we built.
            
            # Since we are CA, ca_found_event isn't set, but we are ready.
            # We need to generate our own client cert signed by our new CA.
            # We can re-use the CAManager's CA key which is now on disk.
            
            # Let's keep the process running? 
            # Note: startsetup.py usually exits. If we become CA, we must Keep Running the signing server!
            # This changes the architecture of startsetup from "run once" to "service".
            # BUT user asked "discover... if not then become CA".
            
            # CRITICAL DECISION:
            # If we become CA, we must run a background process or this script must stay alive.
            # Given the request "these things happen automatically when a host connect", 
            # likely the main app should run this service.
            # However, startsetup.py is seemingly just for ENV setup.
            # If I make startsetup.py block, the user can't run the app?
            # Or maybe the app imports startsetup?
            # Checking imports... peersim.py imports startsetup.load_env_vars and write_env.
            
            # OPTION 1: If CA, fork/detach or rely on the main app to host the CA server.
            # OPTION 2: startsetup.py configures env, but the ACTUAL service runs in the main app (peersim.py).
            
            # Re-reading plan: "[NEW] pki/ca_service.py ... CAManager".
            # Plan said: "Integrate CAManager... Before starting the main application, ensure CA Cert is present".
            
            # IF we are CA, we need the Signing Server to be running. 
            # If `startsetup.py` exits, the server dies.
            # So `startsetup.py` cannot accept the role of running the server permanently tasks.
            # It should mostly likely just "Decide" role and generate certs.
            # The RUNNING of the server must happen in the main application.
            pass

    # For now, let's run the async discovery to completion of "getting certs"
    # If we become CA, we generate keys, but we can't keep the server running here if this script exits.
    # So we will setup the "CA State" (keys on disk) and let the main App run the server if keys exist.
    
    # CHANGING STRATEGY SLIGHTLY:
    # startsetup.py: Determines if CA exists. 
    #   If NO -> Generates CA keys (becomes CA conceptually).
    #   If YES -> Gets signed cert.
    # The actual "Listening for UDP / TCP Signing" should happen in the main app loop.
    
    # Wait, if "Gets signed cert" requires talking to a CA, the CA must be running.
    # So the first node MUST be running the app.
    
    # Implementation:
    # 1. Try to find CA.
    # 2. If found, get cert, exit.
    # 3. If not found, generate CA keys locally, Self-sign client cert, and exit.
    # 4. Main App (peersim/receiver) -> On startup, if CA keys exist, Start Signing Service & UDP Listener.
    
    async def run_setup_logic():
        # Setup UDP listener for 5 seconds
        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
             lambda: asyncio.DatagramProtocol(), local_addr=('0.0.0.0', 0)) # random port to specific port? 
             # No, we need to broadcast to 4434.
             
        # Actually proper reuse of CAManager is hard if we don't let it run.
        # Let's perform a "One-shot discovery".
        
        await ca_mgr.start_discovery()
        print("    Broadcasting 'WHO_IS_CA'...")
        try:
            await asyncio.wait_for(ca_mgr.ca_found_event.wait(), timeout=5.0)
            print(f"    [+] Found CA at {ca_mgr.ca_info}")
            client_cert, ca_cert = await ca_mgr.get_signed_cert(priv_key_pem, f"{user}@{host_ip}")
            with open(cert_file, "wb") as f: f.write(client_cert)
            with open(ca_cert_file, "wb") as f: f.write(ca_cert)
            ca_mgr.stop_discovery()
            
        except asyncio.TimeoutError:
            print("    [-] No CA found. Configuring as CA...")
            # Generate CA Identity
            from pki import utils
            # We use CAManager internal method or logic to generate
            # But we don't start the server here (or we start it just to sign ourselves then stop).
            
            # Manually trigger generation logic
            ca_cert_pem, ca_key_pem = await ca_mgr.become_ca() 
            # This currently starts server + discovery. We should stop them.
             # Wait, become_ca implementation above STARTS server.
            # tailored become_ca returns certs.
            
            # Stop the customized server started by become_ca
            # Accessing private server object is hard.
            # Let's rely on process exit to kill it? Yes.
            
            # We also need to sign our own client cert (cert_file)
            client_cert = utils.sign_csr(
                utils.generate_csr(priv_key_pem, f"{user}@{host_ip}"),
                ca_cert_pem,
                ca_key_pem
            )
            with open(cert_file, "wb") as f: f.write(client_cert)
    
    asyncio.run(run_setup_logic())
    
    # Finally write env
    write_env()

if __name__ == "__main__":
    setup_pki_and_write_env()
