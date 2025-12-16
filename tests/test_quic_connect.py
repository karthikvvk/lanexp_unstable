import asyncio
import os
import tempfile
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta

import types
import sys

# Provide a minimal fake aioquic package when the real one isn't installed so
# unit tests can run in CI/dev without aioquic.
if 'aioquic' not in sys.modules:
    aioquic = types.ModuleType('aioquic')
    aioquic_asyncio = types.ModuleType('aioquic.asyncio')
    def _fake_connect(*args, **kwargs):
        raise RuntimeError("_quic_connect should be patched by tests")
    aioquic_asyncio.connect = _fake_connect

    aioquic_quic = types.ModuleType('aioquic.quic')
    aioquic_quic_configuration = types.ModuleType('aioquic.quic.configuration')

    class QuicConfiguration:
        def __init__(self, *args, **kwargs):
            self.verify_mode = None

        def load_cert_chain(self, cert, key):
            self._chain = (cert, key)

        def load_verify_locations(self, cafile=None):
            self._cafile = cafile

    aioquic_quic_configuration.QuicConfiguration = QuicConfiguration

    sys.modules['aioquic'] = aioquic
    sys.modules['aioquic.asyncio'] = aioquic_asyncio
    sys.modules['aioquic.quic'] = aioquic_quic
    sys.modules['aioquic.quic.configuration'] = aioquic_quic_configuration

import sender_api_functions as sender_mod
from sender_api_functions import quic_connect, QuicSenderConnection


def _make_self_signed_cert(common_name: str, dirpath: str):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    cert_p = os.path.join(dirpath, f"{common_name}.pem")
    key_p = os.path.join(dirpath, f"{common_name}-key.pem")
    with open(cert_p, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_p, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    return cert_p, key_p


def test_quic_connect_loads_client_cert_and_ca():
    td = tempfile.TemporaryDirectory()
    dirp = td.name

    ca_cert_p, ca_key_p = _make_self_signed_cert("test-ca", dirp)
    client_cert_p, client_key_p = _make_self_signed_cert("client", dirp)

    # Replace the _quic_connect implementation to capture configuration
    captured = {}

    class DummyCM:
        def __init__(self, cfg):
            self.cfg = cfg

        async def __aenter__(self):
            class DummyProtocol:
                pass

            return DummyProtocol()

        async def __aexit__(self, exc_type, exc, tb):
            return False

    def fake_connect(*args, **kwargs):
        captured['configuration'] = kwargs.get('configuration')
        return DummyCM(captured['configuration'])

    sender_mod._quic_connect = fake_connect

    async def run():
        conn = await quic_connect('127.0.0.1', port=4433, insecure=False, client_cert=client_cert_p, client_key=client_key_p, ca_cert=ca_cert_p)
        assert isinstance(conn, QuicSenderConnection)
        # client_cert_pem populated
        assert conn.client_cert_pem is not None
        cfg = captured.get('configuration')
        assert cfg is not None
        # CA provided => verify_mode should be required
        assert cfg.verify_mode == ssl.CERT_REQUIRED

    asyncio.get_event_loop().run_until_complete(run())


def test_send_file_prefixes_fingerprint(tmp_path=None):
    # create a temp file
    if tmp_path is None:
        import tempfile
        from pathlib import Path

        td = tempfile.TemporaryDirectory()
        tmp_path = Path(td.name)

    fpath = tmp_path / "hello.txt"
    fpath.write_bytes(b"hello world")

    # create a dummy protocol that records writes
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
            return b""

    class DummyProtocol:
        def __init__(self):
            self.reader = DummyReader()
            self.writer = DummyWriter()

        async def create_stream(self):
            return self.reader, self.writer

    # create a real certificate PEM and use it
    import tempfile
    td = tempfile.TemporaryDirectory()
    cert_p, key_p = _make_self_signed_cert('sender-test', td.name)
    cert_pem = open(cert_p, 'r').read()
    conn = QuicSenderConnection(protocol=DummyProtocol(), _cm=None, client_cert_pem=cert_pem)

    async def run():
        await sender_mod.send_file(conn, str(fpath))
        data = conn.protocol.writer.data
        name_len = int.from_bytes(data[0:2], 'big')
        name = data[2:2+name_len].decode('utf-8')
        assert name.startswith('FP:')

    asyncio.get_event_loop().run_until_complete(run())
