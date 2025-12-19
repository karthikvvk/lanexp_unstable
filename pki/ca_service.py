
import asyncio
import socket
import logging
import json
import os
from typing import Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from pki import utils

# Constants
DISCOVERY_PORT = 4434
SIGNING_PORT = 4435
PEER_DISCOVERY_MSG = b"WHO_IS_PEER"
PEER_RESPONSE_PREFIX = b"I_AM_PEER"

logger = logging.getLogger(__name__)

class CADiscoveryProtocol(asyncio.DatagramProtocol):
    def __init__(self, is_ca: bool, ca_manager):
        self.is_ca = is_ca
        self.ca_manager = ca_manager
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport
        if not self.is_ca:
            # Broadcast WHO_IS_CA
            logger.info("Broadcasting generic CA discovery request...")
            sock = self.transport.get_extra_info('socket')
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.transport.sendto(DISCOVERY_MSG, ('<broadcast>', DISCOVERY_PORT))

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        if self.is_ca and data == DISCOVERY_MSG:
            # I am CA, respond
            response = f"{CA_RESPONSE_PREFIX.decode()} {self.ca_manager.host} {SIGNING_PORT}".encode()
            self.transport.sendto(response, addr)
        elif not self.is_ca and data.startswith(CA_RESPONSE_PREFIX):
            # Found a CA!
            parts = data.decode().split()
            if len(parts) >= 3:
                ca_host = parts[1]
                ca_port = int(parts[2])
                logger.info(f"Discovered CA at {ca_host}:{ca_port}")
                asyncio.create_task(self.ca_manager.on_ca_found(ca_host, ca_port))

class CASigningServer:
    def __init__(self, ca_cert_pem: bytes, ca_key_pem: bytes):
        self.ca_cert_pem = ca_cert_pem
        self.ca_key_pem = ca_key_pem


    async def handle_client(self, reader, writer):
        try:
            # 1. Send CA Cert
            cert_len = len(self.ca_cert_pem)
            writer.write(cert_len.to_bytes(4, 'big'))
            writer.write(self.ca_cert_pem)
            await writer.drain()
            
            # 2. Read CSR size
            size_bytes = await reader.readexactly(4)
            csr_size = int.from_bytes(size_bytes, 'big')
            
            # 3. Read CSR
            csr_pem = await reader.readexactly(csr_size)
            
            # 4. Sign CSR
            client_cert = utils.sign_csr(csr_pem, self.ca_cert_pem, self.ca_key_pem)
            
            # 5. Send back signed cert
            writer.write(len(client_cert).to_bytes(4, 'big'))
            writer.write(client_cert)
            await writer.drain()
            
        except Exception as e:
            logger.error(f"Signing error: {e}")
        finally:
            writer.close()
            await writer.wait_closed()


class CAManager:
    def __init__(self, host: str, cert_dir: str):
        self.host = host
        self.cert_dir = cert_dir
        self.ca_found_event = asyncio.Event()
        self.is_ca = False
        self.ca_info = None
        self.discovery_transport = None

    async def start_discovery(self):
        loop = asyncio.get_running_loop()
        # Bind to 0.0.0.0 to listen, but we need to know how to respond
        self.discovery_transport, _ = await loop.create_datagram_endpoint(
            lambda: CADiscoveryProtocol(self.is_ca, self),
            local_addr=('0.0.0.0', DISCOVERY_PORT),
            allow_broadcast=True
        )
        logger.info(f"Discovery started on port {DISCOVERY_PORT}")

    def stop_discovery(self):
        if self.discovery_transport:
            self.discovery_transport.close()

    async def on_ca_found(self, host: str, port: int):
        if not self.ca_found_event.is_set():
            self.ca_info = (host, port)
            self.ca_found_event.set()

    async def become_ca(self):
        logger.info("No CA found. Becoming CA...")
        self.is_ca = True
        
        # Stop generic discovery to switch to CA mode (responding instead of asking)
        self.stop_discovery()
        
        # Generate CA Cert/Key
        from cryptography.hazmat.primitives.asymmetric import rsa
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        import datetime
        
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"LAN CA"),
        ])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            subject
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        ).sign(key, hashes.SHA256())
        
        ca_cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        ca_key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Save to disk
        with open(os.path.join(self.cert_dir, "ca_cert.pem"), "wb") as f:
            f.write(ca_cert_pem)
        with open(os.path.join(self.cert_dir, "ca_key.pem"), "wb") as f:
            f.write(ca_key_pem)

        # Start Signing Server
        server = CASigningServer(ca_cert_pem, ca_key_pem)
        await asyncio.start_server(server.handle_client, '0.0.0.0', SIGNING_PORT)
        logger.info(f"CA Signing Server started on {SIGNING_PORT}")
        
        # Restart discovery as CA
        await self.start_discovery()
        
        return ca_cert_pem, ca_key_pem

    def check_ca_status(self) -> bool:
        """Check if CA keys exist on disk and update is_ca state."""
        ca_cert_path = os.path.join(self.cert_dir, "ca_cert.pem")
        ca_key_path = os.path.join(self.cert_dir, "ca_key.pem")
        if os.path.exists(ca_cert_path) and os.path.exists(ca_key_path):
            self.is_ca = True
            return True
        return False

    async def start_ca_service(self):
        """Start the CA Signing Server and Discovery Responder if this node is the CA."""
        if not self.is_ca:
            if not self.check_ca_status():
                logger.warning("Cannot start CA service: CA keys not found.")
                return 

        try:
            ca_cert_path = os.path.join(self.cert_dir, "ca_cert.pem")
            ca_key_path = os.path.join(self.cert_dir, "ca_key.pem")
            
            with open(ca_cert_path, "rb") as f: ca_cert_pem = f.read()
            with open(ca_key_path, "rb") as f: ca_key_pem = f.read()
            
            # Start TCP Signing Server
            server = CASigningServer(ca_cert_pem, ca_key_pem)
            # We don't store the server object, letting it run in background loop.
            # Ideally we should keep track of it to close it, but for this service it's fine.
            self.signing_server = await asyncio.start_server(server.handle_client, '0.0.0.0', SIGNING_PORT)
            logger.info(f"CA Signing Server started on {SIGNING_PORT}")
            
            # Start UDP Discovery (as responder since self.is_ca is True)
            await self.start_discovery()
            
        except Exception as e:
            logger.error(f"Failed to start CA service: {e}")

    async def get_signed_cert(self, private_key_pem: bytes, common_name: str) -> Tuple[bytes, bytes]:
        """Returns (client_cert_pem, ca_cert_pem)"""
        csr_pem = utils.generate_csr(private_key_pem, common_name)
        
        host, port = self.ca_info
        reader, writer = await asyncio.open_connection(host, port)
        
        try:
            # 1. Read CA Cert Length
            len_bytes = await reader.readexactly(4)
            ca_cert_len = int.from_bytes(len_bytes, 'big')
            ca_cert_pem = await reader.readexactly(ca_cert_len)
            
            # 2. Send CSR
            writer.write(len(csr_pem).to_bytes(4, 'big'))
            writer.write(csr_pem)
            await writer.drain()
            
            # 3. Read Signed Cert
            len_bytes = await reader.readexactly(4)
            client_cert_len = int.from_bytes(len_bytes, 'big')
            client_cert_pem = await reader.readexactly(client_cert_len)
            
            return client_cert_pem, ca_cert_pem
            
        finally:
            writer.close()
            await writer.wait_closed()



