import hashlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta

from pki.utils import cert_pem_to_der, fingerprint_pem


def test_fingerprint_matches_direct_sha256():
    # create a self-signed cert
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"test.example"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=10))
        .sign(key, hashes.SHA256())
    )

    pem = cert.public_bytes(serialization.Encoding.PEM)
    der = cert_pem_to_der(pem)

    expected = hashlib.sha256(der).hexdigest().lower()
    got = fingerprint_pem(pem)
    assert got == expected
