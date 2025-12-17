
import unittest
import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from pki import utils

class TestPKIUtils(unittest.TestCase):
    def test_csr_generation_and_signing(self):
        # 1. Generate CA Key and Cert
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"Test CA"),
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
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        ).sign(ca_key, hashes.SHA256())
        
        ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
        ca_key_pem = ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        # 2. Generate Client Key
        client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        client_key_pem = client_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        # 3. Generate CSR
        csr_pem = utils.generate_csr(client_key_pem, "Client A")
        self.assertIn(b"BEGIN CERTIFICATE REQUEST", csr_pem)

        # 4. Sign CSR
        client_cert_pem = utils.sign_csr(csr_pem, ca_cert_pem, ca_key_pem)
        self.assertIn(b"BEGIN CERTIFICATE", client_cert_pem)
        
        # 5. Verify validity
        self.assertTrue(utils.verify_cert_validity(client_cert_pem))

if __name__ == "__main__":
    unittest.main()
