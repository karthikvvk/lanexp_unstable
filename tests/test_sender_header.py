import asyncio

from pki.utils import fingerprint_pem
from sender_api_functions import send_bytes, QuicSenderConnection
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta


def make_cert_pem():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"sender.example"),
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
    return cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')


class DummyWriter:
    def __init__(self):
        self.data = bytearray()

    def write(self, b: bytes):
        self.data += b

    async def drain(self):
        return

    def write_eof(self):
        pass


class DummyReader:
    async def read(self, n: int):
        return b""  # no ack


class DummyProtocol:
    def __init__(self):
        self.reader = DummyReader()
        self.writer = DummyWriter()

    async def create_stream(self):
        return self.reader, self.writer


def test_send_bytes_prefixes_fingerprint():
    # create a fake client cert PEM
    cert_pem = make_cert_pem()
    conn = QuicSenderConnection(protocol=DummyProtocol(), _cm=None, client_cert_pem=cert_pem)

    async def run():
        # protocol will keep the writer instance so we can inspect it
        await send_bytes(conn, b"hello", filename_hint="file.bin")
        data = conn.protocol.writer.data
        # parse header
        name_len = int.from_bytes(data[0:2], "big")
        name = data[2 : 2 + name_len].decode("utf-8")
        assert name.startswith("FP:")

    asyncio.get_event_loop().run_until_complete(run())
