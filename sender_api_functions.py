#!/usr/bin/env python3
"""
Sender-side QUIC API functions using aioquic.

This module provides a function-based API so you can reuse a single
QUIC connection and open multiple streams to send files or raw bytes.

Protocol per stream:
    [2 bytes] filename length (big-endian unsigned short)
    [N bytes] filename (UTF-8)
    [8 bytes] file size in bytes (big-endian unsigned long long)
    [..]      file data
"""

import os
import ssl
import struct
from dataclasses import dataclass
from typing import Optional

from aioquic.asyncio import connect as _quic_connect
from aioquic.quic.configuration import QuicConfiguration
from pki.utils import fingerprint_pem, load_cert_pem


# -----------------------------
# Small helper wrapper for the connection
# -----------------------------

@dataclass
class QuicSenderConnection:
    """
    Wrapper representing a persistent QUIC client connection.

    - `protocol` is the aioquic protocol object you can use to create streams.
    - `_cm` is the underlying async context manager used internally.
    """
    protocol: any
    _cm: any
    client_cert_pem: Optional[str] = None

    async def close(self) -> None:
        """
        Gracefully close the underlying QUIC connection and transport.
        """
        # This triggers the same behavior as exiting `async with connect(...)`
        await self._cm.__aexit__(None, None, None)


# -----------------------------
# Internal helpers
# -----------------------------

def _build_header(filename: str, filesize: int) -> bytes:
    """
    Build the metadata header for a stream.

    Header layout:
        [2 bytes] filename length (unsigned short, big-endian)
        [N bytes] filename UTF-8
        [8 bytes] file size (unsigned long long, big-endian)
    """
    filename_bytes = filename.encode("utf-8")
    if len(filename_bytes) > 0xFFFF:
        raise ValueError("Filename too long to encode in header")

    header = struct.pack("!H", len(filename_bytes)) + filename_bytes
    header += struct.pack("!Q", filesize)
    return header


# -----------------------------
# Public API
# -----------------------------

async def quic_connect(
    host: str,
    port: int = 4433,
    *,
    insecure: bool = False,
    server_name: Optional[str] = None,
    alpn_protocol: str = "file-transfer",
    client_cert: Optional[str] = None,
    client_key: Optional[str] = None,
    ca_cert: Optional[str] = None,
) -> QuicSenderConnection:
    """
    Establish a persistent QUIC connection to a receiver and return a
    QuicSenderConnection object.

    Usage:

        conn = await quic_connect("192.168.0.100", 4433, ca_cert="ca.pem")
        await send_file(conn, "/path/to/file.png")
        await conn.close()

    :param host: Receiver hostname or IP.
    :param port: Receiver UDP port.
    :param insecure: If True, disable TLS certificate verification (NOT RECOMMENDED).
    :param server_name: SNI / TLS server name; defaults to `host` if None.
    :param alpn_protocol: ALPN protocol string used by QUIC.
    :param client_cert: Path to client certificate for mTLS.
    :param client_key: Path to client private key for mTLS.
    :param ca_cert: Path to CA certificate for server verification.
    
    :raises ValueError: If insecure=True (to prevent accidental misuse).
    """
    # SECURITY: Prevent insecure mode from accidental use
    if insecure:
        raise ValueError(
            "insecure=True is not allowed. Server certificate verification is mandatory. "
            "Provide ca_cert to verify the server, or set environment variable CA_CERT."
        )
    
    config = QuicConfiguration(
        is_client=True,
        alpn_protocols=[alpn_protocol],
        server_name=server_name or host,
    )

    # Require CA certificate for server verification
    if ca_cert:
        config.load_verify_locations(cafile=ca_cert)
        config.verify_mode = ssl.CERT_REQUIRED
    else:
        raise ValueError(
            "CA_CERT environment variable not set. "
            "Cannot verify server certificate. "
            "Set CA_CERT to the path of your CA certificate."
        )

    # If a client certificate is provided, load it for mTLS
    client_cert_pem = None
    if client_cert and client_key:
        config.load_cert_chain(client_cert, client_key)
        try:
            client_cert_pem = load_cert_pem(client_cert).decode('utf-8')
        except Exception:
            client_cert_pem = None

    # `_quic_connect` returns an async context manager, which we manage manually.
    cm = _quic_connect(
        host=host,
        port=port,
        configuration=config,
        wait_connected=True,
    )

    protocol = await cm.__aenter__()
    return QuicSenderConnection(protocol=protocol, _cm=cm, client_cert_pem=client_cert_pem)


async def send_file(
    connection: QuicSenderConnection,
    file_path: str,
) -> None:
    """
    Send a file over a new QUIC bidirectional stream on an existing connection.

    - Keeps the QUIC connection open.
    - Encodes the filename (optionally with relative directory) in the stream
      header so the receiver can save it with that path under its save_dir.
    """
    abs_path = os.path.abspath(file_path)

    if not os.path.isfile(abs_path):
        # optional: raise or just return
        # raise FileNotFoundError(abs_path)
        return

    # -------- NEW PART: decide what goes into the header --------
    # Try to send a path relative to the sender's CWD.
    # If that doesn't make sense (outside tree), fall back to basename.
    try:
        cwd = os.getcwd()
        rel_path = os.path.relpath(abs_path, cwd)
    except Exception:
        rel_path = os.path.basename(abs_path)

    # If rel_path escapes upwards ("../"), just use basename
    if rel_path.startswith(".."):
        header_name = os.path.basename(abs_path)
    else:
        header_name = rel_path

    # Normalize for cross-platform
    header_name = header_name.replace("\\", "/")
    # If connection has a client cert, compute fingerprint and prefix filename
    try:
        if connection.client_cert_pem:
            fp = fingerprint_pem(connection.client_cert_pem)
            header_name = f"FP:{fp}|{header_name}"
    except Exception:
        # If fingerprinting fails, proceed without prefix
        pass
    # ------------------------------------------------------------

    filesize = os.path.getsize(abs_path)
    header = _build_header(header_name, filesize)

    reader, writer = await connection.protocol.create_stream()

    # Write header first
    writer.write(header)

    # Then write file contents
    with open(abs_path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            writer.write(chunk)

    await writer.drain()
    writer.write_eof()

    # Optional: read ACK (if receiver sends "OK")
    try:
        ack = await reader.read(1024)
        # handle/log ack if you want
    except Exception:
        pass



async def send_bytes(
    connection: QuicSenderConnection,
    data: bytes,
    filename_hint: str = "data.bin",
) -> None:
    """
    Send raw in-memory bytes as a "virtual file" over a new QUIC stream.

    :param connection: QuicSenderConnection returned by `quic_connect`.
    :param data: Bytes to send.
    :param filename_hint: Suggested filename for receiver to use.
    """
    filename = filename_hint
    # If connection has a client cert, prefix filename with fingerprint
    try:
        if connection.client_cert_pem:
            fp = fingerprint_pem(connection.client_cert_pem)
            filename = f"FP:{fp}|{filename}"
    except Exception:
        pass
    filesize = len(data)
    header = _build_header(filename, filesize)

    reader, writer = await connection.protocol.create_stream()

    writer.write(header)
    writer.write(data)

    await writer.drain()
    writer.write_eof()

    try:
        ack = await reader.read(1024)
        # Optional ACK use
    except Exception:
        pass


async def close_connection(connection: QuicSenderConnection) -> None:
    """
    Convenience wrapper to close a QuicSenderConnection.

    Same as calling `await connection.close()`.
    """
    await connection.close()


async def send_auth(
    connection: QuicSenderConnection,
    password: str,
) -> bool:
    """
    Send authentication password to receiver.
    
    :param connection: QuicSenderConnection
    :param password: Password string
    :return: True if auth accepted, False otherwise
    """
    # Use internal _build_header helper but with special filename
    filename = "__AUTH__"
    data = password.encode("utf-8")
    filesize = len(data)
    
    header = _build_header(filename, filesize)
    
    try:
        reader, writer = await connection.protocol.create_stream()
        
        writer.write(header)
        writer.write(data)
        await writer.drain()
        writer.write_eof()
        
        # Read response
        response = await reader.read(1024)
        return response == b"AUTH_OK"
        
    except Exception:
        return False
