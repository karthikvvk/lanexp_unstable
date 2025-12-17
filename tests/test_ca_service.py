
import unittest
import asyncio
import os
import shutil
import tempfile
from pki import ca_service
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

class TestCAService(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.ca_dir = os.path.join(self.tmp_dir, "ca")
        self.client_dir = os.path.join(self.tmp_dir, "client")
        os.makedirs(self.ca_dir)
        os.makedirs(self.client_dir)

    async def asyncTearDown(self):
        shutil.rmtree(self.tmp_dir)

    async def test_ca_generation_and_signing(self):
        # 1. Start CA Manager (Node A)
        ca_manager = ca_service.CAManager("127.0.0.1", self.ca_dir)
        
        # Force become CA
        ca_cert_pem, _ = await ca_manager.become_ca()
        self.assertTrue(os.path.exists(os.path.join(self.ca_dir, "ca_cert.pem")))

        # 2. Client (Node B) gets signed
        # Mocking discovery by manually setting info (since UDP broadcast on localhost in test might be flaky or need delay)
        client_manager = ca_service.CAManager("127.0.0.1", self.client_dir)
        client_manager.ca_info = ("127.0.0.1", ca_service.SIGNING_PORT)
        
        # Generate Client Key
        client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        client_key_pem = client_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Request Signing
        client_cert_pem, received_ca_cert = await client_manager.get_signed_cert(client_key_pem, "ClientNode")
        
        self.assertTrue(len(client_cert_pem) > 0)
        self.assertEqual(received_ca_cert, ca_cert_pem)

if __name__ == "__main__":
    unittest.main()
