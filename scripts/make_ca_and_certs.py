#!/usr/bin/env python3
import asyncio
import ssl
import os
import tempfile
from datetime import datetime, timedelta, timezone
import ipaddress
import sys

# Ensure project root is on sys.path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from aioquic.asyncio import serve
from aioquic.quic.configuration import QuicConfiguration
from sender_api_functions import quic_connect, send_bytes, close_connection


def make_ca_and_certs(tmpdir):
    ca_path = os.environ.get("CA_CERT")

    if ca_path and os.path.exists(ca_path):
        raise RuntimeError(
            "CA already exists. Refusing to generate a new CA. "
            "This would fork the trust domain."
        )
    # create CA
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"Test CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    # server cert
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"localhost")])
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName(u"localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    # client cert
    client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"client")])
    client_cert = (
        x509.CertificateBuilder()
        .subject_name(client_name)
        .issuer_name(ca_name)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .sign(ca_key, hashes.SHA256())
    )

    ca_p = os.path.join(tmpdir, 'ca.pem')
    server_p = os.path.join(tmpdir, 'server.pem')
    server_key_p = os.path.join(tmpdir, 'server-key.pem')
    client_p = os.path.join(tmpdir, 'client.pem')
    client_key_p = os.path.join(tmpdir, 'client-key.pem')

    with open(ca_p, 'wb') as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    with open(server_p, 'wb') as f:
        f.write(server_cert.public_bytes(serialization.Encoding.PEM))
    with open(server_key_p, 'wb') as f:
        f.write(server_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    with open(client_p, 'wb') as f:
        f.write(client_cert.public_bytes(serialization.Encoding.PEM))
    with open(client_key_p, 'wb') as f:
        f.write(client_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))

    return ca_p, server_p, server_key_p, client_p, client_key_p


async def run_test():
    tmpdir = tempfile.mkdtemp()
    ca_p, server_p, server_key_p, client_p, client_key_p = make_ca_and_certs(tmpdir)

    config = QuicConfiguration(is_client=False, alpn_protocols=['file-transfer'])
    config.load_cert_chain(server_p, server_key_p)
    config.load_verify_locations(cafile=ca_p)
    import ssl as sslmod
    config.verify_mode = sslmod.CERT_REQUIRED

    async def _stream_handler(reader, writer):
        print('Stream handler invoked')
        # try to show extra info
        try:
            info = writer.get_extra_info('ssl_object')
            print('ssl_object:', info)
            if info is not None:
                try:
                    der = info.getpeercert(binary_form=True)
                    print('peer der len', len(der) if der else None)
                except Exception as e:
                    print('error getting peercert:', e)
        except Exception as e:
            print('get_extra_info failed:', e)

        # Try helper that inspects the QUIC protocol/transport for peer cert
        try:
            from pki.utils import get_peer_cert_pem_from_writer, fingerprint_pem

            pem = get_peer_cert_pem_from_writer(writer)
            if pem:
                print('peer cert PEM found, fingerprint:', fingerprint_pem(pem))
            else:
                print('no peer cert PEM extracted')
        except Exception as e:
            print('error extracting peer cert via helper:', e)
        # read filename length
        try:
            raw = await reader.readexactly(2)
            n = int.from_bytes(raw, 'big')
            fname = (await reader.readexactly(n)).decode('utf-8')
            print('fname:', fname)
            raw = await reader.readexactly(8)
            size = int.from_bytes(raw, 'big')
            data = await reader.readexactly(size)
            print('received data len', len(data))
            writer.write(b'OK')
            await writer.drain()
        except Exception as e:
            print('stream handler exception:', e)

    def stream_handler(reader, writer):
        # Spawn the coroutine to handle the stream (avoid "coroutine was never awaited")
        asyncio.create_task(_stream_handler(reader, writer))

    server = await serve(host='127.0.0.1', port=4434, configuration=config, stream_handler=stream_handler)
    print('server started')

    # create client and send a small payload
    conn = await quic_connect(host='127.0.0.1', port=4434, insecure=False, client_cert=client_p, client_key=client_key_p, ca_cert=ca_p)
    print('client connected')
    await send_bytes(conn, b'hello', filename_hint='test.txt')
    await close_connection(conn)

    server.close()
    # Some aioquic versions provide `wait_closed()`, others do not.
    try:
        await server.wait_closed()
    except AttributeError:
        # fallback: give the loop a moment to clean up
        await asyncio.sleep(0.1)


if __name__ == '__main__':
    asyncio.run(run_test())
