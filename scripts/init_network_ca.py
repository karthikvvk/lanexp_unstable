#!/usr/bin/env python3
import os
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta, timezone

OUTDIR = "pkica_export"
CA_CERT = os.path.join(OUTDIR, "ca.pem")
CA_KEY  = os.path.join(OUTDIR, "ca.key")

if os.path.exists(CA_CERT) or os.path.exists(CA_KEY):
    raise RuntimeError("CA already exists. Refusing to overwrite.")

os.makedirs(OUTDIR, exist_ok=True)

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, u"LANFX Network CA"),
])

cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.now(timezone.utc))
    .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .sign(key, hashes.SHA256())
)

with open(CA_KEY, "wb") as f:
    f.write(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )

with open(CA_CERT, "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

print("[+] Network CA created at pkica_export/")
