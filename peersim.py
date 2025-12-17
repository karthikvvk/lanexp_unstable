#!/usr/bin/env python3
"""
P2P QUIC Connection Simulator

Simulates two peers (Peer A and Peer B) establishing secure QUIC connections
with certificate-based authentication (TOFU model).

Usage:
    python peer_simulator.py --mode setup          # Generate certs for both peers
    python peer_simulator.py --mode peer-a         # Run as Peer A (receiver)
    python peer_simulator.py --mode peer-b         # Run as Peer B (sender)
    python peer_simulator.py --mode test-send      # Test file send
    python peer_simulator.py --mode test-recv      # Test file receive
    python peer_simulator.py --mode full-test      # Full bidirectional test
"""

import asyncio
import os
import sys
import argparse
import json
import tempfile
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Tuple
import ipaddress

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from startsetup import load_env_vars, write_env
from sender_api_functions import quic_connect, send_file, close_connection, send_auth
from receiver_api_functions import start_receiver, stop_receiver
from pki.utils import fingerprint_pem, load_cert_pem, verify_cert_validity
from pki.store import PeerStore


# ==================== CONFIG ====================

class PeerConfig:
    """Configuration for a single peer"""
    def __init__(self, name: str, host: str, port: int, base_dir: Path):
        self.name = name
        self.host = host
        self.port = port
        self.base_dir = base_dir
        self.cert_file = base_dir / f"{name}_cert.pem"
        self.key_file = base_dir / f"{name}_key.pem"
        self.ca_cert_file = base_dir / "ca_cert.pem"
        self.peers_store_file = base_dir / f"{name}_peers.json"
        self.test_files_dir = base_dir / f"{name}_files"
        
    def ensure_dirs(self):
        """Create necessary directories"""
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.test_files_dir.mkdir(parents=True, exist_ok=True)
        

class SimulationEnv:
    """Global simulation environment"""
    def __init__(self, work_dir: Optional[Path] = None):
        self.work_dir = work_dir or Path(tempfile.gettempdir()) / "quic_peers_sim"
        self.work_dir.mkdir(parents=True, exist_ok=True)
        
        self.peer_a = PeerConfig("peer_a", "127.0.0.1", 4433, self.work_dir)
        self.peer_b = PeerConfig("peer_b", "127.0.0.1", 4434, self.work_dir)
        
        # Ensure directories
        self.peer_a.ensure_dirs()
        self.peer_b.ensure_dirs()
        
        print(f"\n[*] Simulation environment at: {self.work_dir}")

        
        print(f"\n[*] Simulation environment at: {self.work_dir}")


async def ensure_ca_running(base_dir: Path):
    """Check if we are CA and start signing server if so"""
    ca_key = base_dir / "ca_key.pem"
    ca_cert = base_dir / "ca_cert.pem"
    
    if ca_key.exists() and ca_cert.exists():
        print("[*] CA keys found. Starting CA Service...")
        from pki.ca_service import CAManager
        # Host doesn't matter for serving, but CAManager needs it.
        # We just need to start the server.
        # Reuse CAManager logic? Or just start SigningServer directly?
        # CAManager encapsulates discovery too. Better to use it.
        mgr = CAManager("0.0.0.0", str(base_dir))
        
        # Load keys to start server
        with open(ca_cert, "rb") as f: c = f.read()
        with open(ca_key, "rb") as f: k = f.read()
        
        from pki.ca_service import CASigningServer, SIGNING_PORT
        server = CASigningServer(c, k)
        await asyncio.start_server(server.handle_client, '0.0.0.0', SIGNING_PORT)
        
        # Also start discovery responder
        mgr.is_ca = True
        await mgr.start_discovery()
        print(f"[+] CA Service Running (Sign Port: {SIGNING_PORT})")

# ==================== CERTIFICATE GENERATION ====================

def setup_certificates(env: SimulationEnv):
    """Generate CA and peer certificates"""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from datetime import datetime, timedelta, timezone
    
    print("\n" + "="*60)
    print("[*] SETTING UP CERTIFICATES")
    print("="*60)
    
    # Generate CA key
    print("\n[+] Generating CA private key...")
    ca_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Generate CA certificate
    print("[+] Generating CA certificate...")
    ca_subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"QUIC Test CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Test Org"),
    ])
    
    ca_cert = x509.CertificateBuilder().subject_name(
        ca_subject
    ).issuer_name(
        ca_subject
    ).public_key(
        ca_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    ).sign(ca_key, hashes.SHA256())
    
    # Save CA cert
    ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
    with open(env.work_dir / "ca_cert.pem", "wb") as f:
        f.write(ca_cert_pem)
    print(f"    ✓ Saved to {env.work_dir / 'ca_cert.pem'}")
    
    # Generate peer certificates
    for peer_config in [env.peer_a, env.peer_b]:
        print(f"\n[+] Generating {peer_config.name} certificate...")
        
        # Generate peer key
        peer_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        # Generate peer certificate (signed by CA)
        peer_subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, peer_config.name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Test Org"),
        ])
        
        peer_cert = x509.CertificateBuilder().subject_name(
            peer_subject
        ).issuer_name(
            ca_subject
        ).public_key(
            peer_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(u"localhost"),
                x509.DNSName(peer_config.name),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            ]),
            critical=False,
        ).sign(ca_key, hashes.SHA256())
        
        # Save peer cert
        peer_cert_pem = peer_cert.public_bytes(serialization.Encoding.PEM)
        with open(peer_config.cert_file, "wb") as f:
            f.write(peer_cert_pem)
        print(f"    ✓ Certificate: {peer_config.cert_file}")
        
        # Save peer key
        peer_key_pem = peer_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(peer_config.key_file, "wb") as f:
            f.write(peer_key_pem)
        os.chmod(peer_config.key_file, 0o600)
        print(f"    ✓ Private Key: {peer_config.key_file}")
        
        # Print fingerprint
        fp = fingerprint_pem(peer_cert_pem.decode())
        print(f"    ✓ Fingerprint: {fp}")


# ==================== PEER STORE INITIALIZATION ====================

def initialize_peer_stores(env: SimulationEnv):
    """Initialize peer stores with pre-approved peers"""
    print("\n" + "="*60)
    print("[*] INITIALIZING PEER STORES (TOFU)")
    print("="*60)
    
    # Load peer certificates
    with open(env.peer_a.cert_file, "rb") as f:
        peer_a_cert = f.read().decode()
    with open(env.peer_b.cert_file, "rb") as f:
        peer_b_cert = f.read().decode()
    
    # Get fingerprints
    peer_a_fp = fingerprint_pem(peer_a_cert)
    peer_b_fp = fingerprint_pem(peer_b_cert)
    
    print(f"\n[+] Peer A fingerprint: {peer_a_fp}")
    print(f"[+] Peer B fingerprint: {peer_b_fp}")
    
    # Initialize Peer A's store (knows about Peer B)
    print(f"\n[+] Initializing {env.peer_a.name} peer store...")
    store_a = PeerStore(str(env.peer_a.peers_store_file))
    
    # Add Peer B as pending, then approve
    store_a.add_pending(cert_pem=peer_b_cert, note="Peer B (simulator)")
    store_a.approve_peer(peer_b_fp, password="test_password")
    print(f"    ✓ Added Peer B as TRUSTED")
    
    # Initialize Peer B's store (knows about Peer A)
    print(f"\n[+] Initializing {env.peer_b.name} peer store...")
    store_b = PeerStore(str(env.peer_b.peers_store_file))
    
    # Add Peer A as pending, then approve
    store_b.add_pending(cert_pem=peer_a_cert, note="Peer A (simulator)")
    store_b.approve_peer(peer_a_fp, password="test_password")
    print(f"    ✓ Added Peer A as TRUSTED")
    
    # Print peer store contents
    print(f"\n[+] Peer A store contents:")
    for fp, rec in store_a.list_peers().items():
        print(f"    {fp[:16]}... → {rec.get('status')} (added: {rec.get('added_at')})")
    
    print(f"\n[+] Peer B store contents:")
    for fp, rec in store_b.list_peers().items():
        print(f"    {fp[:16]}... → {rec.get('status')} (added: {rec.get('added_at')})")


# ==================== RECEIVER (PEER A) ====================

async def run_receiver(env: SimulationEnv, duration: int = 60):
    """Run Peer A as receiver"""
    print("\n" + "="*60)
    print(f"[*] STARTING RECEIVER (Peer A on {env.peer_a.host}:{env.peer_a.port})")
    print("="*60)
    
    # Set environment variables
    os.environ["CA_CERT"] = str(env.work_dir / "ca_cert.pem")
    os.environ["PEERS_FILE"] = str(env.peer_a.peers_store_file)
    os.environ["P2P_PASSWORD"] = "supersecret" # Explicitly set for test
    
    server = None
    
    def on_file_received(filepath: str, filesize: int):
        print(f"\n[✓] FILE RECEIVED: {filepath} ({filesize} bytes)")
    
    try:
        await start_receiver(
            host=env.peer_a.host,
            port=env.peer_a.port,
            certificate=str(env.peer_a.cert_file),
            private_key=str(env.peer_a.key_file),
            ca_cert=str(env.work_dir / "ca_cert.pem"),
            on_file_received=on_file_received,
            save_dir=str(env.peer_a.test_files_dir),
            require_client_cert=True,  # Enforce mTLS
        )
        
        # Keep running for specified duration
        print(f"\n[*] Listening for {duration} seconds...")
        await asyncio.sleep(duration)
        
    except Exception as e:
        print(f"\n[✗] ERROR: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if server:
            await stop_receiver(server)
        print(f"\n[*] Receiver stopped")


# ==================== SENDER (PEER B) ====================

async def run_sender(env: SimulationEnv, files: list[str]):
    """Run Peer B as sender"""
    print("\n" + "="*60)
    print(f"[*] STARTING SENDER (Peer B, target: {env.peer_a.host}:{env.peer_a.port})")
    print("="*60)
    
    # Set environment variables
    os.environ["CA_CERT"] = str(env.work_dir / "ca_cert.pem")
    os.environ["PEERS_FILE"] = str(env.peer_b.peers_store_file)
    os.environ["CLIENT_CERT"] = str(env.peer_b.cert_file)
    os.environ["CLIENT_KEY"] = str(env.peer_b.key_file)
    
    try:
        # Wait a bit for receiver to start
        await asyncio.sleep(2)
        
        print(f"\n[*] Connecting to receiver at {env.peer_a.host}:{env.peer_a.port}...")
        
        conn = await quic_connect(
            host=env.peer_a.host,
            port=env.peer_a.port,
            insecure=False,
            server_name=env.peer_a.name,
            client_cert=str(env.peer_b.cert_file),
            client_key=str(env.peer_b.key_file),
            ca_cert=str(env.work_dir / "ca_cert.pem"),
        )
        
        print(f"[✓] Connected!")
        
        # Authenticate
        print(f"[*] Authenticating with password...")
        # Note: In a real scenario, we don't know the password unless user provides it.
        # But for test, we assume we know the target's P2P_PASSWORD.
        # Peer A (receiver) will check P2P_PASSWORD env var. 
        # But verification env needs to set it.
        # Let's assume P2P_PASSWORD is set in env for both? 
        # Or we pass it. But run_sender uses env vars primarily.
        
        # We need to send the password that Peer A expects.
        # In this simulation, assuming shared secret "supersecret".
        auth_success = await send_auth(conn, "supersecret")
        if auth_success:
             print(f"[✓] Authentication SUCCESS")
        else:
             print(f"[✗] Authentication FAILED")
             # await close_connection(conn)
             # return

        
        # Send files
        for filepath in files:
            if os.path.isfile(filepath):
                print(f"\n[*] Sending file: {filepath}")
                await send_file(conn, filepath)
                print(f"[✓] File sent!")
            else:
                print(f"[✗] File not found: {filepath}")
        
        await close_connection(conn)
        print(f"\n[✓] Connection closed")
        
    except Exception as e:
        print(f"\n[✗] ERROR: {e}")
        import traceback
        traceback.print_exc()


# ==================== TEST HELPERS ====================

def create_test_files(env: SimulationEnv):
    """Create sample test files"""
    print("\n[*] Creating test files...")
    
    test_files = []
    
    # Create small text file
    test_file_1 = env.peer_b.test_files_dir / "test_message.txt"
    with open(test_file_1, "w") as f:
        f.write(f"Hello from Peer B!\n")
        f.write(f"Timestamp: {datetime.now()}\n")
        f.write(f"This is a test message for P2P file transfer.\n")
    test_files.append(str(test_file_1))
    print(f"    ✓ Created {test_file_1.name}")
    
    # Create medium binary file (1 MB)
    test_file_2 = env.peer_b.test_files_dir / "test_data.bin"
    with open(test_file_2, "wb") as f:
        f.write(b"BINARY_DATA_" * (1024 * 100))  # ~1.2 MB
    test_files.append(str(test_file_2))
    print(f"    ✓ Created {test_file_2.name} ({os.path.getsize(test_file_2) / (1024*1024):.2f} MB)")
    
    # Create JSON config file
    test_file_3 = env.peer_b.test_files_dir / "config.json"
    with open(test_file_3, "w") as f:
        json.dump({
            "peer": "peer_b",
            "timestamp": datetime.now().isoformat(),
            "test": True,
            "files": ["test_message.txt", "test_data.bin"]
        }, f, indent=2)
    test_files.append(str(test_file_3))
    print(f"    ✓ Created {test_file_3.name}")
    
    return test_files


# ==================== FULL TEST ====================

async def run_full_test(env: SimulationEnv):
    """Run receiver and sender concurrently"""
    print("\n" + "="*70)
    print("[*] STARTING FULL BIDIRECTIONAL TEST")
    print("="*70)
    
    test_files = create_test_files(env)
    
    # Run receiver and sender concurrently
    receiver_task = asyncio.create_task(run_receiver(env, duration=30))
    sender_task = asyncio.create_task(run_sender(env, files=test_files))
    
    # Wait for both to complete
    await asyncio.gather(receiver_task, sender_task)
    
    # Verify transferred files
    print("\n" + "="*70)
    print("[*] VERIFICATION")
    print("="*70)
    
    received_files = list(env.peer_a.test_files_dir.rglob("*"))
    received_files = [f for f in received_files if f.is_file()]
    
    if received_files:
        print(f"\n[✓] Received {len(received_files)} files:")
        for f in received_files:
            print(f"    - {f.name} ({f.stat().st_size} bytes)")
    else:
        print(f"\n[✗] No files received!")


# ==================== CLI ====================

def main():
    parser = argparse.ArgumentParser(
        description="P2P QUIC Connection Simulator with PKI/TOFU",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Setup certificates and peer stores
  %(prog)s --mode setup
  
  # Run receiver (Peer A)
  %(prog)s --mode peer-a
  
  # Run sender (Peer B) in another terminal
  %(prog)s --mode peer-b --files file1.txt file2.bin
  
  # Full test (both peers in one run)
  %(prog)s --mode full-test
  
  # Use custom work directory
  %(prog)s --mode setup --workdir /tmp/my_peers
        """
    )
    
    parser.add_argument(
        "--mode",
        choices=["setup", "peer-a", "peer-b", "full-test"],
        default="setup",
        help="Simulation mode"
    )
    
    parser.add_argument(
        "--workdir",
        type=Path,
        default=None,
        help="Working directory for simulation (default: /tmp/quic_peers_sim)"
    )
    
    parser.add_argument(
        "--files",
        nargs="+",
        default=[],
        help="Files to send (for peer-b mode)"
    )
    
    args = parser.parse_args()
    
    # Create environment
    env = SimulationEnv(work_dir=args.workdir)
    
    print(f"""
    ╔════════════════════════════════════════════════════════════╗
    ║   P2P QUIC Connection Simulator with PKI/TOFU             ║
    ║                                                            ║
    ║   Work Dir: {str(env.work_dir):45} ║
    ╚════════════════════════════════════════════════════════════╝
    """)
    
    try:
        if args.mode == "setup":
            setup_certificates(env)
            initialize_peer_stores(env)
            print("\n[✓] Setup complete! You can now run peers.")
            print(f"\n[*] Start Peer A (receiver) in one terminal:")
            print(f"    python peer_simulator.py --mode peer-a --workdir {env.work_dir}")
            print(f"\n[*] Start Peer B (sender) in another terminal:")
            print(f"    python peer_simulator.py --mode peer-b --workdir {env.work_dir}")
            
        elif args.mode == "peer-a":
            asyncio.run(run_receiver(env))
            
        elif args.mode == "peer-b":
            if not args.files:
                test_files = create_test_files(env)
            else:
                test_files = args.files
            asyncio.run(run_sender(env, files=test_files))
            
        elif args.mode == "full-test":
            asyncio.run(run_full_test(env))
    
    except KeyboardInterrupt:
        print("\n\n[*] Interrupted by user")
    except Exception as e:
        print(f"\n[✗] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()